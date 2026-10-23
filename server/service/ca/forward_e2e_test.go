package ca_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net/http"
	"testing"

	"github.com/effective-security/trustyca/privpb"
	"github.com/effective-security/trustyca/server/service/backend"
	"github.com/effective-security/xdb"

	"github.com/effective-security/trustyca/server/service/shared"

	"github.com/effective-security/porto/gserver"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/porto/xhttp/identity"
	"github.com/effective-security/trustyca/api/client"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/authctx"
	"github.com/effective-security/trustyca/internal/config"
	"github.com/effective-security/trustyca/internal/db"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/server/appcontainer"
	"github.com/effective-security/trustyca/server/service/ca"
	"github.com/effective-security/trustyca/tests/testutils"
	"github.com/effective-security/xpki/certutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"
	"google.golang.org/grpc/codes"
)

// The labels of the CA the forwarding test creates in its org
const (
	fwdRootLabel   = "FWD_ROOT"
	fwdRootProfile = "fwd_root"
	fwdPeerProfile = "fwd_peer"
)

// TestService_ForwardOverMTLS runs the CA service of a web process, which
// has no backend service, against the backend listener of the dev
// configuration over mTLS (DESIGN.md section 2.1): the CA service dials it
// with the `ca` service client (trustyca-peer) and forwards the context of
// its caller, which the backend authorizes again with the grants of the DB
// before it runs the method as that caller. The AIA identity reaches
// SignOCSP only, a caller without a role is refused by the backend, and a
// precondition refusal keeps its HTTP status through the forwarding. The
// data protection seed is the environment's, as for every process that
// uses the dev DB.
func TestService_ForwardOverMTLS(t *testing.T) {
	testutils.SetDataProtectionSeed(t)
	ctx := context.Background()

	cfg, err := testutils.LoadConfig("UNIT_TEST")
	require.NoError(t, err)
	closer := appcontainer.NewCloser(4)
	t.Cleanup(func() { _ = closer.Close() })
	container, err := appcontainer.NewContainerFactory(closer).
		WithConfigurationProvider(func() (*config.Configuration, error) {
			return cfg, nil
		}).
		CreateContainerWithDependencies()
	require.NoError(t, err)
	var (
		provider   db.Provider
		authorizer authctx.Authorizer
	)
	require.NoError(t, container.Invoke(func(p db.Provider, a authctx.Authorizer) {
		provider = p
		authorizer = a
	}))

	// the backend listener of the dev configuration on its own port: TLS
	// identities, deny by default, the forwarded callers authorized again
	devBackend := cfg.HTTPServers[config.BackendServerName]
	require.NotNil(t, devBackend)
	backendCfg := *devBackend
	backendURL := testutils.CreateURL("https", "localhost")
	backendCfg.ListenURLs = []string{backendURL}
	backendCfg.Services = []string{backend.ServiceName}
	server, err := gserver.Start("ForwardTestBackend", &backendCfg, container, map[string]gserver.ServiceFactory{
		backend.ServiceName: backend.Factory,
	}, gserver.WithUnaryServerInterceptor(authctx.NewAuthUnaryBackendInterceptor(authorizer)))
	require.NoError(t, err)
	t.Cleanup(server.Close)

	// the service clients of the dev configuration, dialing that port
	var clients []client.Config
	for _, c := range cfg.Clients {
		if c.Name == client.ClientNameCA || c.Name == client.ClientNameAIA {
			c.ServerURL = map[string]string{
				config.BackendServerName: backendURL,
			}
			clients = append(clients, c)
		}
	}
	require.Len(t, clients, 2)
	factory, err := client.NewFactory(clients)
	require.NoError(t, err)

	// the CA service of a web process: the backend over mTLS, and no CA table
	locator := shared.NewBackendLocator(nil, factory, client.ClientNameCA, config.BackendServerName)
	wfe := ca.New(locator)
	t.Cleanup(wfe.Close)

	// the org of the test and its Owner, and a user without a grant in it
	newUser := func(name string) *model.User {
		id := provider.NextID()
		login := &model.Login{
			ID:         id,
			ExternalID: id.String(),
			Name:       name,
			Email:      id.String() + "@example.com",
			Provider:   pb.IDP_Github,
		}
		_, user, err := provider.LoginUser(ctx, login)
		require.NoError(t, err)
		t.Cleanup(func() { _, _ = provider.DeleteUserByEmail(ctx, login.Email) })
		return user
	}
	owner := newUser("Forward Owner")
	stranger := newUser("Forward Stranger")
	org, err := provider.RegisterOrg(ctx, &model.Org{Name: "Forward Org"}, owner.ID.UInt64())
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = provider.DeleteOrg(ctx, org.ID.UInt64()) })
	orgID := org.ID.String()

	// userCtx is the context the WFE builds for a user token of the org
	userCtx := func(user *model.User, role pb.Role_Enum) context.Context {
		uid := identity.NewIdentity("user", user.ID.String(), orgID, map[string]any{
			"sub":                user.ID.String(),
			"email":              user.Email,
			"name":               user.Name,
			authctx.ClaimOrg:     orgID,
			authctx.ClaimOrgRole: role.String(),
		}, "tok", "Bearer", identity.MethodJWT)
		return authctx.NewTrustyCtx(ctx, identity.NewRequestContext(uid, "/wfe"))
	}
	ownerCtx := userCtx(owner, pb.Role_Owner)

	// a profile is managed by the web process, the root is created by the
	// backend for the Owner
	rootProfile, err := wfe.RegisterProfile(ownerCtx, &pb.RegisterProfileRequest{
		Profile: &pb.CertProfile{
			Label:       fwdRootProfile,
			IssuerLabel: model.AnyIssuerLabel,
			Expiry:      "8760h",
			Backdate:    "30m",
			Usages:      []string{"cert sign", "crl sign"},
			CAConstraint: &pb.CAConstraint{
				IsCA:       true,
				MaxPathLen: -1,
			},
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = provider.DeleteProfile(ctx, org.ID.UInt64(), mustID(t, rootProfile.ID)) })
	rootReq := &pb.RegisterIssuerRequest{
		Label:   fwdRootLabel,
		Type:    pb.AuthorityType_Root,
		Subject: &pb.X509Subject{CommonName: "Forward Root"},
		Profile: fwdRootProfile,
	}

	// the backend refuses a forwarded caller without a role in the org
	_, err = wfe.RegisterIssuer(userCtx(stranger, pb.Role_None), rootReq)
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, httperror.NewFromPb(err).RPCStatus, err.Error())

	root, err := wfe.RegisterIssuer(ownerCtx, rootReq)
	require.NoError(t, err)
	t.Cleanup(func() {
		// the key of the root is destroyed in its provider through the
		// backend, then the rows are removed
		_, _ = wfe.UpdateIssuer(ownerCtx, &pb.UpdateIssuerRequest{ID: root.ID, Status: pb.IssuerStatus_Archived})
		_, _ = wfe.UpdateIssuer(ownerCtx, &pb.UpdateIssuerRequest{ID: root.ID, Status: pb.IssuerStatus_Destroyed})
		roots, err := wfe.ListRoots(ownerCtx, &pb.ListRootsRequest{})
		if err == nil {
			for _, r := range roots.Roots {
				_, _ = provider.DeleteRoot(ctx, org.ID.UInt64(), mustID(t, r.ID))
			}
		}
		_, _ = provider.DeleteIssuer(ctx, org.ID.UInt64(), mustID(t, root.ID))
	})
	assert.Equal(t, pb.IssuerStatus_Active, root.Status)

	// a precondition refusal of the backend keeps HTTP 409 conflict
	_, err = wfe.ActivateIssuer(ownerCtx, &pb.ActivateIssuerRequest{ID: root.ID, Certificate: root.Certificate})
	require.Error(t, err)
	herr := httperror.NewFromPb(err)
	assert.Equal(t, codes.FailedPrecondition, herr.RPCStatus)
	assert.Equal(t, http.StatusConflict, herr.HTTPStatus)
	assert.Equal(t, httperror.CodeConflict, herr.Code)
	assert.Equal(t, "issuer is not pending", herr.Message, err.Error())

	// the Owner signs through the backend, which records the Owner as the
	// actor of the issue event
	peerProfile, err := wfe.RegisterProfile(ownerCtx, &pb.RegisterProfileRequest{
		Profile: &pb.CertProfile{
			Label:             fwdPeerProfile,
			IssuerLabel:       fwdRootLabel,
			Expiry:            "168h",
			Backdate:          "30m",
			Usages:            []string{"signing", "key encipherment", "server auth"},
			AllowedExtensions: []string{"2.5.29.17"},
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = provider.DeleteProfile(ctx, org.ID.UInt64(), mustID(t, peerProfile.ID)) })
	signed, err := wfe.SignCertificate(ownerCtx, &pb.SignCertificateRequest{
		Profile: fwdPeerProfile,
		Request: newCSR(t, "fwd.example.com"),
		SAN:     []string{"fwd.example.com"},
	})
	require.NoError(t, err)
	crt := signed.Certificate
	t.Cleanup(func() { _, _ = provider.DeleteCertificate(ctx, org.ID.UInt64(), mustID(t, crt.ID)) })
	assert.Equal(t, orgID, crt.OrgID)
	assert.Equal(t, root.SKID, crt.IKID)
	issued, err := provider.ListEvents(ctx, &query.ListEventsRequest{OrgID: org.ID.UInt64(), Type: pb.EventType_CertificateIssued, Limit: 10})
	require.NoError(t, err)
	require.Len(t, issued.Rows, 1)
	assert.Equal(t, owner.Email, issued.Rows[0].Email.String())
	assert.Equal(t, backend.EventSource, issued.Rows[0].Source.String())

	// the AIA identity signs OCSP and nothing else
	aia, aiaCloser, err := factory.BackendClient(client.ClientNameAIA, config.BackendServerName)
	require.NoError(t, err)
	t.Cleanup(func() { _ = aiaCloser.Close() })
	x509Cert, err := certutil.ParseFromPEM([]byte(crt.Pem))
	require.NoError(t, err)
	rootCert, err := certutil.ParseFromPEM([]byte(root.Certificate))
	require.NoError(t, err)
	ocspReq, err := ocsp.CreateRequest(x509Cert, rootCert, nil)
	require.NoError(t, err)
	ocspRes, err := aia.SignOCSP(ctx, &pb.OCSPRequest{Der: ocspReq})
	require.NoError(t, err)
	parsed, err := ocsp.ParseResponseForCert(ocspRes.Der, x509Cert, rootCert)
	require.NoError(t, err)
	assert.Equal(t, ocsp.Good, parsed.Status)
	_, err = aia.SignCertificate(ctx, &privpb.SignCertificateRequest{OrgID: orgID, Profile: fwdPeerProfile, Request: newCSR(t, "aia.example.com")})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, httperror.NewFromPb(err).RPCStatus, err.Error())
}

// newCSR returns the PEM encoding of a certificate request for a new key
func newCSR(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// mustID parses an ID of the API
func mustID(t *testing.T, id string) uint64 {
	t.Helper()
	v, err := xdb.ParseID(id)
	require.NoError(t, err)
	return v.UInt64()
}
