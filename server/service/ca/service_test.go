package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"
	"time"

	"github.com/effective-security/porto/xhttp/identity"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/authctx"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/tests/testutils"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xpki/authority"
	"github.com/effective-security/xpki/csr"
	"github.com/stretchr/testify/require"
)

// test fixtures: org 1 with projects 201 (active) and 203 (inactive);
// project 301 belongs to org 2
var (
	testOrg = &model.Org{
		ID:     xdb.NewID(1),
		Alias:  "cp_test",
		Name:   "Test Org",
		Status: pb.ItemStatus_Active,
	}
	inactiveOrg = &model.Org{
		ID:     xdb.NewID(3),
		Alias:  "cp_gone",
		Name:   "Gone Org",
		Status: pb.ItemStatus_Inactive,
	}
	testProject = &model.Project{
		ID:     xdb.NewID(201),
		OrgID:  xdb.NewID(1),
		Alias:  "test",
		Name:   "Test",
		Status: pb.ItemStatus_Active,
	}
	inactiveProject = &model.Project{
		ID:     xdb.NewID(203),
		OrgID:  xdb.NewID(1),
		Alias:  "old",
		Name:   "Old",
		Status: pb.ItemStatus_Inactive,
	}
	foreignProject = &model.Project{
		ID:     xdb.NewID(301),
		OrgID:  xdb.NewID(2),
		Alias:  "foreign",
		Name:   "Foreign",
		Status: pb.ItemStatus_Active,
	}
)

// testCallerEmail is the email in the token of every testCtx caller
const testCallerEmail = "caller@example.com"

// testIssuerLabel is the label of the issuer of the test authority
const testIssuerLabel = "L2_CA"

// testProfile is the end-entity profile the test issuer serves
const testProfile = "peer"

// fakeAuthorizer resolves projects from a fixed set; the CA service does
// not resolve grants itself, the interceptor does
type fakeAuthorizer struct {
	projects map[uint64]*model.Project
}

func newFakeAuthorizer() *fakeAuthorizer {
	return &fakeAuthorizer{
		projects: map[uint64]*model.Project{
			testProject.ID.UInt64():     testProject,
			inactiveProject.ID.UInt64(): inactiveProject,
			foreignProject.ID.UInt64():  foreignProject,
		},
	}
}

func (f *fakeAuthorizer) Grants(_ context.Context, orgID, userID xdb.ID) (*authctx.Grants, error) {
	if orgID.UInt64() == 0 {
		return nil, authctx.ErrOrgNotSelected
	}
	return authctx.GrantsFromMemberships(nil, orgID, userID), nil
}

func (f *fakeAuthorizer) Project(_ context.Context, orgID, projectID xdb.ID) (*model.Project, error) {
	p, ok := f.projects[projectID.UInt64()]
	if !ok || p.OrgID.UInt64() != orgID.UInt64() || p.Status != pb.ItemStatus_Active {
		return nil, authctx.ErrAccessDenied
	}
	return p, nil
}

func (f *fakeAuthorizer) CheckRole(ctx context.Context, orgID, projectID, userID xdb.ID, _ ...string) (pb.Role_Enum, *authctx.Grants, error) {
	if projectID.UInt64() != 0 {
		if _, err := f.Project(ctx, orgID, projectID); err != nil {
			return pb.Role_None, nil, err
		}
	}
	g, err := f.Grants(ctx, orgID, userID)
	if err != nil {
		return pb.Role_None, nil, err
	}
	return pb.Role_None, g, authctx.ErrInsufficientRole
}

func (f *fakeAuthorizer) InvalidateUser(context.Context, string) {}

func (f *fakeAuthorizer) InvalidateProject(context.Context, string) {}

// testCtx returns a request context for the user with the org selected in
// the token. An empty orgID means no org is selected.
func testCtx(userID, orgID string) context.Context {
	claims := map[string]any{
		"sub":   userID,
		"email": testCallerEmail,
		"name":  "Caller",
	}
	if orgID != "" {
		claims[authctx.ClaimOrg] = orgID
	}
	uid := identity.NewIdentity("user", userID, orgID, claims, "tok", "Bearer", identity.MethodJWT)
	return authctx.NewTrustyCtx(context.Background(), identity.NewRequestContext(uid, "/test"))
}

// serviceCtx returns a request context of a trusted service caller over
// mTLS, which has no org in its identity
func serviceCtx(role string) context.Context {
	uid := identity.NewIdentity(role, role, "", map[string]any{}, "", "", identity.MethodCertificate)
	return authctx.NewTrustyCtx(context.Background(), identity.NewRequestContext(uid, "/test"))
}

// testAuthority is an in-memory authority with one issuing CA under a root
type testAuthority struct {
	root      *testutils.TestCA
	ca        *testutils.TestCA
	authority *authority.Authority
	issuer    *authority.Issuer
}

// newTestAuthority builds the authority of the tests: the issuer
// testIssuerLabel serves testProfile
func newTestAuthority(t *testing.T) *testAuthority {
	t.Helper()
	root := testutils.NewTestCA(t, "Test Root", nil)
	ca := testutils.NewTestCA(t, "Test L2", root)

	profiles := map[string]*authority.CertProfile{
		testProfile: {
			IssuerLabel: testIssuerLabel,
			Expiry:      csr.Duration(168 * time.Hour),
			Backdate:    csr.Duration(30 * time.Minute),
			Usage:       []string{"signing", "key encipherment", "server auth", "client auth"},
		},
	}
	cfg := &authority.IssuerConfig{
		Label:    testIssuerLabel,
		Profiles: profiles,
		AIA: &authority.AIAConfig{
			OCSPExpiry: 8 * time.Hour,
		},
	}
	issuer, err := authority.CreateIssuer(cfg,
		[]byte(testutils.CertPEM(ca.Cert)),
		nil,
		[]byte(testutils.CertPEM(root.Cert)),
		ca.Key)
	require.NoError(t, err)

	auth, err := authority.NewAuthority(&authority.Config{
		Authority: &authority.CAConfig{},
		Profiles:  profiles,
	}, nil)
	require.NoError(t, err)
	require.NoError(t, auth.AddIssuer(issuer))

	return &testAuthority{
		root:      root,
		ca:        ca,
		authority: auth,
		issuer:    issuer,
	}
}

// newCSR returns the DER and PEM encodings of a certificate request for
// a new key
func newCSR(t *testing.T, cn string) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}, key)
	require.NoError(t, err)
	return der, pem.EncodeToMemory(&pem.Block{Type: csrPEMType, Bytes: der})
}
