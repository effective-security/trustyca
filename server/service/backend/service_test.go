package backend

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/effective-security/porto/xhttp/identity"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/authctx"
	core "github.com/effective-security/trustyca/internal/ca"
	"github.com/effective-security/trustyca/internal/ca/pbconv"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/mocks/mocktrustycadb"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/cryptoprov"
	"github.com/effective-security/xpki/cryptoprov/inmemcrypto"
	"github.com/effective-security/xpki/csr"
	"github.com/effective-security/xpki/dataprotection"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// test fixtures: org 1 with projects 201 and 202 (active) and 203
// (inactive); project 301 belongs to org 2
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
	siblingProject = &model.Project{
		ID:     xdb.NewID(202),
		OrgID:  xdb.NewID(1),
		Alias:  "sibling",
		Name:   "Sibling",
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

// Users of the tests, as the fake authorizer grants them: an Admin of every
// org, a Viewer and an Admin of project 201 only, and one without grants
const (
	orgAdminUser      = "42"
	projectViewerUser = "77"
	projectAdminUser  = "78"
	strangerUser      = "99"
)

// Labels of the CA of the tests: org 1 has the root testRootLabel, which
// signs CAs with testCAProfile, and the issuing CA testIssuerLabel, which
// serves the end-entity profile testProfile and allows testOCSPProfile
const (
	testRootLabel   = "ROOT"
	testRootProfile = "ROOT"
	testCAProfile   = "CA"
	testIssuerLabel = "L2_CA"
	testProfile     = "peer"
	testOCSPProfile = "ocsp"
	testDPSeed      = "service-test-seed"
)

// testOrgID returns the org of the CA of the tests. It is a new ID on every
// call: xdb.ID caches its string form without synchronization, so parallel
// tests never share one.
func testOrgID() xdb.ID {
	return xdb.NewID(1)
}

func notFoundErr(table string, id any) error {
	return xdb.CheckNotFoundError(sql.ErrNoRows, table, id)
}

// fakeAuthorizer resolves projects and grants from a fixed set: the
// interceptor authorizes the scope of a request, and the service the rows
// it resolves by ID (Scope.RowAccess) and the projects a list covers
type fakeAuthorizer struct {
	projects map[uint64]*model.Project
}

func newFakeAuthorizer() *fakeAuthorizer {
	return &fakeAuthorizer{
		projects: map[uint64]*model.Project{
			testProject.ID.UInt64():     testProject,
			siblingProject.ID.UInt64():  siblingProject,
			inactiveProject.ID.UInt64(): inactiveProject,
			foreignProject.ID.UInt64():  foreignProject,
		},
	}
}

func (f *fakeAuthorizer) Grants(_ context.Context, orgID, userID xdb.ID) (*authctx.Grants, error) {
	if orgID.UInt64() == 0 {
		return nil, authctx.ErrOrgNotSelected
	}
	g := &authctx.Grants{
		OrgID:        orgID,
		UserID:       userID,
		ProjectRoles: map[uint64]pb.Role_Enum{},
	}
	switch xdb.IDString(userID.UInt64()) {
	case orgAdminUser:
		g.OrgRole = pb.Role_Admin
	case projectViewerUser:
		g.ProjectRoles[testProject.ID.UInt64()] = pb.Role_Viewer
	case projectAdminUser:
		g.ProjectRoles[testProject.ID.UInt64()] = pb.Role_Admin
	}
	return g, nil
}

func (f *fakeAuthorizer) Project(_ context.Context, orgID, projectID xdb.ID) (*model.Project, error) {
	p, ok := f.projects[projectID.UInt64()]
	if !ok || p.OrgID.UInt64() != orgID.UInt64() || p.Status != pb.ItemStatus_Active {
		return nil, authctx.ErrAccessDenied
	}
	return p, nil
}

func (f *fakeAuthorizer) CheckRole(ctx context.Context, orgID, projectID, userID xdb.ID, allowedRoles ...string) (pb.Role_Enum, *authctx.Grants, error) {
	if projectID.UInt64() != 0 {
		if _, err := f.Project(ctx, orgID, projectID); err != nil {
			return pb.Role_None, nil, err
		}
	}
	g, err := f.Grants(ctx, orgID, userID)
	if err != nil {
		return pb.Role_None, nil, err
	}
	role := g.HighestRole(projectID.UInt64(), allowedRoles)
	if role == pb.Role_None {
		return pb.Role_None, g, authctx.ErrInsufficientRole
	}
	return role, g, nil
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

// apiKeyCtx returns a request context of an API key of the org with the
// read and issue scopes, restricted to the project when one is given
func apiKeyCtx(orgID, projectID string) context.Context {
	return apiKeyScopedCtx(orgID, projectID, "ca:read", "certs:issue")
}

// apiKeyScopedCtx returns a request context of an API key of the org with
// the scopes, restricted to the project when one is given
func apiKeyScopedCtx(orgID, projectID string, scopes ...string) context.Context {
	claims := map[string]any{
		"sub":                "key-1",
		authctx.ClaimOrg:     orgID,
		authctx.ClaimOrgRole: pb.Role_APIKey.String(),
		authctx.ClaimScope:   scopes,
	}
	if projectID != "" {
		claims[authctx.ClaimProject] = projectID
	}
	uid := identity.NewIdentity("apikey", "key-1", orgID, claims, "tok", "Bearer", identity.MethodJWT)
	return authctx.NewTrustyCtx(context.Background(), identity.NewRequestContext(uid, "/test"))
}

// serviceCtx returns a request context of a trusted service caller over
// mTLS, which has no org in its identity
func serviceCtx(role string) context.Context {
	uid := identity.NewIdentity(role, role, "", map[string]any{}, "", "", identity.MethodCertificate)
	return authctx.NewTrustyCtx(context.Background(), identity.NewRequestContext(uid, "/test"))
}

// eventRecorder captures the events the service emits
type eventRecorder struct {
	mu     sync.Mutex
	events []*model.Event
}

func (r *eventRecorder) record(evt *model.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, evt)
}

// count returns the number of events of the type
func (r *eventRecorder) count(typ pb.EventType_Enum) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, evt := range r.events {
		if evt.Type == typ {
			n++
		}
	}
	return n
}

// last returns the last event of the type, or nil
func (r *eventRecorder) last(typ pb.EventType_Enum) *model.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := len(r.events) - 1; i >= 0; i-- {
		if r.events[i].Type == typ {
			return r.events[i]
		}
	}
	return nil
}

// caRows are the issuer and profile rows the mock DB serves to the
// registry; tests add rows and the mutation expectations update them
type caRows struct {
	mu       sync.Mutex
	nextID   uint64
	issuers  map[uint64]*model.Issuer
	profiles map[uint64]*model.CertificateProfile
}

func newCARows() *caRows {
	return &caRows{
		nextID:   5000,
		issuers:  map[uint64]*model.Issuer{},
		profiles: map[uint64]*model.CertificateProfile{},
	}
}

func (r *caRows) id() xdb.ID {
	r.nextID++
	return xdb.NewID(r.nextID)
}

// ownID returns an ID of the same value that shares no string cache with
// the fixtures of the package, which parallel tests share
func ownID(id xdb.ID) xdb.ID {
	return xdb.NewID(id.UInt64())
}

// addIssuer stores the row, assigning an ID and timestamps when it has none
func (r *caRows) addIssuer(m *model.Issuer) *model.Issuer {
	r.mu.Lock()
	defer r.mu.Unlock()
	row := *m
	if row.ID.IsZero() {
		row.ID = r.id()
	}
	row.OrgID = ownID(row.OrgID)
	row.ProjectID = ownID(row.ProjectID)
	row.ParentID = ownID(row.ParentID)
	if row.CreatedAt.IsZero() {
		row.CreatedAt = xdb.UTC(time.Now())
		row.UpdatedAt = row.CreatedAt
	}
	r.issuers[row.ID.UInt64()] = &row
	res := row
	return &res
}

// addProfile stores the row, replacing the one with its label in its scope
func (r *caRows) addProfile(m *model.CertificateProfile) *model.CertificateProfile {
	r.mu.Lock()
	defer r.mu.Unlock()
	row := *m
	row.OrgID = ownID(row.OrgID)
	row.ProjectID = ownID(row.ProjectID)
	for _, cur := range r.profiles {
		if cur.OrgID.UInt64() == row.OrgID.UInt64() && cur.ProjectID.UInt64() == row.ProjectID.UInt64() && cur.Label == row.Label {
			row.ID = cur.ID
			row.CreatedAt = cur.CreatedAt
			row.UpdatedAt = xdb.UTC(cur.UpdatedAt.UTC().Add(time.Millisecond))
		}
	}
	if row.ID.IsZero() {
		row.ID = r.id()
		row.CreatedAt = xdb.UTC(time.Now())
		row.UpdatedAt = row.CreatedAt
	}
	if row.Status == pb.ItemStatus_Unknown {
		row.Status = pb.ItemStatus_Active
	}
	r.profiles[row.ID.UInt64()] = &row
	res := row
	return &res
}

// update applies a change to the stored issuer row and returns the copy
func (r *caRows) update(id xdb.ID, mod func(m *model.Issuer)) *model.Issuer {
	r.mu.Lock()
	defer r.mu.Unlock()
	m := r.issuers[id.UInt64()]
	mod(m)
	m.UpdatedAt = xdb.UTC(m.UpdatedAt.UTC().Add(time.Millisecond))
	res := *m
	return &res
}

func (r *caRows) getIssuer(_ context.Context, id uint64) (*model.Issuer, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if m, ok := r.issuers[id]; ok {
		res := *m
		return &res, nil
	}
	return nil, notFoundErr("issuer", id)
}

func (r *caRows) findIssuer(_ context.Context, orgID, projectID uint64, label string) (*model.Issuer, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, m := range r.issuers {
		if m.OrgID.UInt64() == orgID && m.ProjectID.UInt64() == projectID && m.Label == label {
			res := *m
			return &res, nil
		}
	}
	return nil, notFoundErr("issuer", fmt.Sprintf("%d/%d/%s", orgID, projectID, label))
}

func (r *caRows) getIssuerBySKID(_ context.Context, skid string) (*model.Issuer, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, m := range r.issuers {
		if m.Skid == skid {
			res := *m
			return &res, nil
		}
	}
	return nil, notFoundErr("issuer", skid)
}

func (r *caRows) getProfile(_ context.Context, id uint64) (*model.CertificateProfile, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if m, ok := r.profiles[id]; ok {
		res := *m
		return &res, nil
	}
	return nil, notFoundErr("certificate_profile", id)
}

func (r *caRows) findProfile(_ context.Context, orgID, projectID uint64, label string) (*model.CertificateProfile, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, m := range r.profiles {
		if m.OrgID.UInt64() == orgID && m.ProjectID.UInt64() == projectID && m.Label == label {
			res := *m
			return &res, nil
		}
	}
	return nil, notFoundErr("certificate_profile", fmt.Sprintf("%d/%d/%s", orgID, projectID, label))
}

func (r *caRows) deleteProfile(_ context.Context, orgID, id uint64) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if m, ok := r.profiles[id]; ok && m.OrgID.UInt64() == orgID {
		delete(r.profiles, id)
		return 1, nil
	}
	return 0, nil
}

// testCA is the CA of the service tests: the issuer registry over the
// mock DB, whose reads serve the rows, with the root, the issuing CA and
// the profiles of org 1 created through internal/ca with the inmem crypto
// provider. The mutations of the mock DB are expected by each test.
type testCA struct {
	ctx        context.Context
	prov       cryptoprov.Provider
	keys       *core.Keys
	registry   *core.Registry
	cadb       *mocktrustycadb.MockCaDb
	orgsdb     *mocktrustycadb.MockOrgsDb
	events     *eventRecorder
	rows       *caRows
	root       *model.Issuer
	issuer     *model.Issuer
	issuerCert *x509.Certificate
	peer       *model.CertificateProfile
}

// rootProfileDef is a self-signing CA profile
func rootProfileDef(label string) *pb.CertProfile {
	return &pb.CertProfile{
		Label:       label,
		IssuerLabel: model.AnyIssuerLabel,
		Expiry:      "43800h",
		Backdate:    "30m",
		Usages:      []string{"cert sign", "crl sign"},
		CAConstraint: &pb.CAConstraint{
			IsCA:       true,
			MaxPathLen: -1,
		},
	}
}

// caProfileDef is the profile a parent signs issuing CAs with: the CAs get
// path length zero and sign no subordinate CA
func caProfileDef(label, issuerLabel string) *pb.CertProfile {
	return caProfileDefWithPathLen(label, issuerLabel, 0)
}

// caProfileDefWithPathLen is the profile a parent signs subordinate CAs
// with the path length: the number of CAs they may sign in turn
func caProfileDefWithPathLen(label, issuerLabel string, maxPathLen int32) *pb.CertProfile {
	return &pb.CertProfile{
		Label:       label,
		IssuerLabel: issuerLabel,
		Expiry:      "8760h",
		Backdate:    "30m",
		Usages:      []string{"cert sign", "crl sign"},
		CAConstraint: &pb.CAConstraint{
			IsCA:       true,
			MaxPathLen: maxPathLen,
		},
	}
}

// peerProfileDef is an end-entity profile
func peerProfileDef(label, issuerLabel, expiry string) *pb.CertProfile {
	return &pb.CertProfile{
		Label:       label,
		IssuerLabel: issuerLabel,
		Expiry:      expiry,
		Backdate:    "30m",
		Usages:      []string{"signing", "key encipherment", "server auth", "client auth"},
		AllowedExtensions: []string{
			"2.5.29.17",
		},
	}
}

// ocspProfileDef is a delegated OCSP responder profile for any issuer
func ocspProfileDef(label string) *pb.CertProfile {
	return &pb.CertProfile{
		Label:       label,
		IssuerLabel: model.AnyIssuerLabel,
		Expiry:      "168h",
		Backdate:    "30m",
		Usages:      []string{"ocsp signing"},
		OcspNoCheck: true,
	}
}

// newTestCA builds the CA of the tests
func newTestCA(t testing.TB, ctrl *gomock.Controller) *testCA {
	t.Helper()
	ctx := context.Background()
	prov := inmemcrypto.NewProvider()
	crypto, err := cryptoprov.New(prov, nil)
	require.NoError(t, err)
	dp, err := dataprotection.NewSymmetric([]byte(testDPSeed))
	require.NoError(t, err)

	rows := newCARows()
	cadb := mocktrustycadb.NewMockCaDb(ctrl)
	cadb.EXPECT().GetIssuer(gomock.Any(), gomock.Any()).DoAndReturn(rows.getIssuer).AnyTimes()
	cadb.EXPECT().FindIssuer(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(rows.findIssuer).AnyTimes()
	cadb.EXPECT().GetIssuerBySKID(gomock.Any(), gomock.Any()).DoAndReturn(rows.getIssuerBySKID).AnyTimes()
	cadb.EXPECT().GetProfile(gomock.Any(), gomock.Any()).DoAndReturn(rows.getProfile).AnyTimes()
	cadb.EXPECT().FindProfile(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(rows.findProfile).AnyTimes()
	orgsdb := mocktrustycadb.NewMockOrgsDb(ctrl)
	events := &eventRecorder{}
	orgsdb.EXPECT().TryCreateEvent(gomock.Any()).Do(events.record).AnyTimes()

	keys := core.NewKeys(crypto, dp)
	registry := core.NewRegistry(cadb, keys, core.Options{})
	tca := &testCA{
		ctx:      ctx,
		prov:     prov,
		keys:     keys,
		registry: registry,
		cadb:     cadb,
		orgsdb:   orgsdb,
		events:   events,
		rows:     rows,
	}

	tca.addProfile(testOrgID(), xdb.ID(0), caProfileDef(testCAProfile, testRootLabel))
	tca.root = tca.newRoot(t, testOrgID(), xdb.ID(0), testRootLabel)
	tca.issuer = tca.newChild(t, tca.root, testCAProfile, testOrgID(), xdb.ID(0), testIssuerLabel, pb.AuthorityType_Issuing, &pb.IssuerConfig{
		AllowedProfiles: []string{testOCSPProfile},
		OcspExpiry:      "8h",
	})
	tca.issuerCert, err = certutil.ParseFromPEM([]byte(tca.issuer.Pem))
	require.NoError(t, err)
	tca.peer = tca.addProfile(testOrgID(), xdb.ID(0), peerProfileDef(testProfile, testIssuerLabel, "168h"))
	return tca
}

// service returns the backend service of the tests over the CA
func (tca *testCA) service() *Service {
	return New(tca.cadb, tca.orgsdb, newFakeAuthorizer(), tca.registry)
}

// noCA returns a backend service without an issuer registry, over the DB of
// the CA: the methods that use a key are Unavailable
func (tca *testCA) noCA() *Service {
	return New(tca.cadb, tca.orgsdb, newFakeAuthorizer(), nil)
}

// addProfile stores a profile of the scope
func (tca *testCA) addProfile(orgID, projectID xdb.ID, def *pb.CertProfile) *model.CertificateProfile {
	m, err := model.NewCertificateProfile(orgID, projectID, def)
	if err != nil {
		panic(err)
	}
	return tca.rows.addProfile(m)
}

// newRoot creates and stores a self-signed root of the scope
func (tca *testCA) newRoot(t testing.TB, orgID, projectID xdb.ID, label string) *model.Issuer {
	t.Helper()
	profile, err := pbconv.ProfileFromPb(rootProfileDef(testRootProfile))
	require.NoError(t, err)
	m, err := tca.keys.NewRootIssuer(tca.ctx, &core.IssuerRequest{
		OrgID:     orgID,
		ProjectID: projectID,
		Label:     label,
		Type:      pb.AuthorityType_Root,
		Subject:   &csr.X509Subject{CommonName: label + " Root"},
		Provider:  tca.prov,
	}, testRootProfile, profile)
	require.NoError(t, err)
	return tca.rows.addIssuer(m)
}

// newChild creates and stores an issuer signed by the parent with the CA
// profile of the parent's scope
func (tca *testCA) newChild(t testing.TB, parent *model.Issuer, caProfile string, orgID, projectID xdb.ID, label string, typ pb.AuthorityType_Enum, cfg *pb.IssuerConfig) *model.Issuer {
	t.Helper()
	res, err := tca.registry.Resolve(tca.ctx, &core.ResolveRequest{
		OrgID:       parent.OrgID,
		ProjectID:   parent.ProjectID,
		Profile:     caProfile,
		IssuerLabel: parent.Label,
	})
	require.NoError(t, err)
	m, err := tca.keys.NewSignedIssuer(tca.ctx, &core.IssuerRequest{
		OrgID:     orgID,
		ProjectID: projectID,
		Label:     label,
		Type:      typ,
		Subject:   &csr.X509Subject{CommonName: label + " CA"},
		Provider:  tca.prov,
		Config:    cfg,
	}, res)
	require.NoError(t, err)
	return tca.rows.addIssuer(m)
}

// newPending creates and stores a Pending issuer of the scope
func (tca *testCA) newPending(t testing.TB, orgID, projectID xdb.ID, label string) *model.Issuer {
	t.Helper()
	m, err := tca.keys.NewPendingIssuer(tca.ctx, &core.IssuerRequest{
		OrgID:     orgID,
		ProjectID: projectID,
		Label:     label,
		Type:      pb.AuthorityType_Issuing,
		Subject:   &csr.X509Subject{CommonName: label + " CA"},
		Provider:  tca.prov,
	})
	require.NoError(t, err)
	return tca.rows.addIssuer(m)
}

// sign issues an end-entity certificate with the issuing CA and the peer
// profile, outside the service
func (tca *testCA) sign(t testing.TB, cn string) *x509.Certificate {
	t.Helper()
	res, err := tca.registry.Resolve(tca.ctx, &core.ResolveRequest{OrgID: testOrgID(), Profile: testProfile})
	require.NoError(t, err)
	_, csrPEM := newCSR(t, cn)
	crt, _, err := res.Issuer.Sign(csr.SignRequest{
		Request: string(csrPEM),
		Profile: res.ProfileName,
	})
	require.NoError(t, err)
	return crt
}

// newCSR returns the DER and PEM encodings of a certificate request for
// a new key
func newCSR(t testing.TB, cn string) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}, key)
	require.NoError(t, err)
	return der, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// keyPEM returns the PEM encoding of the key
func keyPEM(t testing.TB, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
}
