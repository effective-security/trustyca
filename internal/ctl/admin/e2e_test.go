package admin_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"net"
	"testing"

	"github.com/effective-security/trustyca/server/service/backend"

	"github.com/alecthomas/kong"
	"github.com/effective-security/porto/gserver"
	"github.com/effective-security/porto/xhttp/identity"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/authctx"
	"github.com/effective-security/trustyca/internal/config"
	"github.com/effective-security/trustyca/internal/ctl"
	"github.com/effective-security/trustyca/internal/ctl/admin"
	"github.com/effective-security/trustyca/internal/db"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/privpb"
	"github.com/effective-security/trustyca/server/appcontainer"
	adminsvc "github.com/effective-security/trustyca/server/service/admin"
	casvc "github.com/effective-security/trustyca/server/service/ca"
	"github.com/effective-security/trustyca/tests/testutils"
	xctl "github.com/effective-security/x/ctl"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xpki/certutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// The platform intermediate of etc/dev/ca-config.local.yaml that signs the
// issuing CAs of the orgs, and the CA profile it allows
const (
	e2eParentLabel = "trusty.l1"
	e2eCAProfile   = "tenant_ca"
	e2eIssuerLabel = "issuing"
	// e2eRole is the identity of the operator's client certificate on the
	// backend listener
	e2eRole = "trustyca-admin"
)

// TestCA_EndToEnd runs the CA and Admin services of the app container over
// the configured database and drives them with the CTL commands as the
// trustyca-admin identity: it onboards a new org under the platform
// intermediate with the dev template profiles, signs a certificate of the
// new issuing CA through the API, then lists, reads, revokes, publishes and
// archives through the commands. The data protection seed is the
// environment's, as for every process that uses the dev DB.
func TestCA_EndToEnd(t *testing.T) {
	testutils.SetDataProtectionSeed(t)
	ctx := context.Background()

	closer := appcontainer.NewCloser(4)
	t.Cleanup(func() { _ = closer.Close() })
	container, err := appcontainer.NewContainerFactory(closer).
		WithConfigurationProvider(func() (*config.Configuration, error) {
			return testutils.LoadConfig("UNIT_TEST")
		}).
		CreateContainerWithDependencies()
	require.NoError(t, err)
	var provider db.Provider
	require.NoError(t, container.Invoke(func(p db.Provider) { provider = p }))

	server, err := gserver.Start("CTLTest", &gserver.Config{
		ListenURLs: []string{testutils.CreateURL("http", "")},
		Services:   []string{casvc.ServiceName, backend.ServiceName, adminsvc.ServiceName},
	}, container, map[string]gserver.ServiceFactory{
		casvc.ServiceName:    casvc.Factory,
		backend.ServiceName:  backend.Factory,
		adminsvc.ServiceName: adminsvc.Factory,
	})
	require.NoError(t, err)
	t.Cleanup(server.Close)
	addr := backendServer(t, server.Service(casvc.ServiceName).(pb.CAServer), server.Service(adminsvc.ServiceName).(privpb.AdminServer))

	// the API client the test verifies with
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	client := pb.NewCAClient(conn)

	// the CTL
	var out bytes.Buffer
	cli := &ctl.Cli{
		Version: xctl.VersionFlag("test"),
		Storage: t.TempDir(),
	}
	cli.WithWriter(&out).WithErrWriter(&out)
	parser, err := kong.New(cli, kong.Name("trustycactl-test"), kong.Writers(&out, &out), xctl.BoolPtrMapper)
	require.NoError(t, err)
	_, err = parser.Parse([]string{"-s", addr, "--storage", cli.Storage})
	require.NoError(t, err)
	run := func(cmd interface{ Run(admin.App) error }) string {
		t.Helper()
		out.Reset()
		require.NoError(t, cmd.Run(cli))
		return out.String()
	}
	runJSON := func(cmd interface{ Run(admin.App) error }, res any) {
		t.Helper()
		cli.O = "json"
		defer func() { cli.O = "" }()
		require.NoError(t, json.Unmarshal([]byte(run(cmd)), res))
	}

	// the org of the test
	ownerID := provider.NextID()
	login := &model.Login{
		ID:         ownerID,
		ExternalID: ownerID.String(),
		Name:       "CTL Owner",
		Email:      ownerID.String() + "@example.com",
		Provider:   pb.IDP_Github,
	}
	_, owner, err := provider.LoginUser(ctx, login)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = provider.DeleteUserByEmail(ctx, login.Email) })
	org, err := provider.RegisterOrg(ctx, &model.Org{Name: "CTL Org"}, owner.ID.UInt64())
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = provider.DeleteOrg(ctx, org.ID.UInt64()) })
	orgID := org.ID.String()

	// the platform intermediate, through the support list
	var platform pb.IssuersResponse
	runJSON(&admin.IssuerListCmd{Platform: true, Label: e2eParentLabel, Status: "Active"}, &platform)
	require.Len(t, platform.Issuers, 1, "the bootstrap registered %s", e2eParentLabel)
	parent := platform.Issuers[0]
	assert.Empty(t, parent.OrgID)
	assert.Equal(t, pb.AuthorityType_Intermediate, parent.Type)
	assert.Contains(t, parent.Config.AllowedProfiles, e2eCAProfile)

	// onboard
	printed := run(&admin.OrgBootstrapCmd{
		OrgScope:  admin.OrgScope{Org: orgID},
		Templates: templatesDir,
		Parent:    e2eParentLabel,
		Profile:   e2eCAProfile,
		Label:     e2eIssuerLabel,
		SubjectFlags: admin.SubjectFlags{
			CN:           "CTL Org Issuing CA",
			Organization: "CTL Org",
		},
		IssuerSettings: admin.IssuerSettings{
			CrlURL:      "http://localhost:8880/v1/crl/${ISSUER_ID}",
			OcspURL:     "http://localhost:8880/v1/ocspi/${ISSUER_ID}",
			CrlExpiry:   "48h",
			OcspExpiry:  "1h",
			OcspProfile: "ocsp",
		},
	})
	assert.Contains(t, printed, "4 profiles registered")
	issuer, err := client.GetIssuer(ctx, &pb.GetIssuerRequest{OrgID: orgID, Label: e2eIssuerLabel})
	require.NoError(t, err)
	t.Cleanup(func() {
		// the key is destroyed in its provider through the service, then
		// the rows are removed; the CRL follows the issuer
		_, _ = client.UpdateIssuer(ctx, &pb.UpdateIssuerRequest{OrgID: orgID, ID: issuer.ID, Status: pb.IssuerStatus_Archived})
		_, _ = client.UpdateIssuer(ctx, &pb.UpdateIssuerRequest{OrgID: orgID, ID: issuer.ID, Status: pb.IssuerStatus_Destroyed})
		_, _ = provider.DeleteIssuer(ctx, org.ID.UInt64(), mustID(t, issuer.ID))
	})
	assert.Equal(t, pb.IssuerStatus_Active, issuer.Status)
	assert.Equal(t, pb.AuthorityType_Issuing, issuer.Type)
	assert.Equal(t, parent.ID, issuer.ParentID)
	assert.Equal(t, parent.SKID, issuer.IKID, "signed by the platform intermediate")
	assert.Equal(t, []string{"ocsp"}, issuer.Config.AllowedProfiles, "the wildcard template")
	issuerCert, err := certutil.ParseFromPEM([]byte(issuer.Certificate))
	require.NoError(t, err)
	parentCert, err := certutil.ParseFromPEM([]byte(parent.Certificate))
	require.NoError(t, err)
	require.NoError(t, issuerCert.CheckSignatureFrom(parentCert))
	assert.True(t, issuerCert.IsCA)
	assert.Equal(t, 0, issuerCert.MaxPathLen, "the tenant CA signs no subordinate")
	assert.NotEmpty(t, issuer.Intermediates, "the chain to the root")
	assert.NotEmpty(t, issuer.Root)

	profiles, err := client.ListProfiles(ctx, &pb.ListProfilesRequest{OrgID: orgID})
	require.NoError(t, err)
	require.Len(t, profiles.Profiles, 4)
	t.Cleanup(func() {
		for _, p := range profiles.Profiles {
			_, _ = provider.DeleteProfile(ctx, org.ID.UInt64(), mustID(t, p.ID))
		}
	})
	byLabel := map[string]string{}
	for _, p := range profiles.Profiles {
		byLabel[p.Label] = p.IssuerLabel
	}
	assert.Equal(t, map[string]string{
		"client": e2eIssuerLabel,
		"ocsp":   model.AnyIssuerLabel,
		"peer":   e2eIssuerLabel,
		"server": e2eIssuerLabel,
	}, byLabel)
	printed = run(&admin.ProfileListCmd{OrgScope: admin.OrgScope{Org: orgID}})
	assert.Contains(t, printed, "server")
	printed = run(&admin.ProfileGetCmd{OrgScope: admin.OrgScope{Org: orgID}, Label: "ocsp"})
	assert.Contains(t, printed, "ocsp signing")

	// a second onboarding of the org is refused: the issuer label is taken
	out.Reset()
	err = (&admin.OrgBootstrapCmd{
		OrgScope:  admin.OrgScope{Org: orgID},
		Templates: templatesDir,
		Parent:    parent.ID,
		Profile:   e2eCAProfile,
		Label:     e2eIssuerLabel,
	}).Run(cli)
	assert.EqualError(t, err, "conflict: issuer label is already registered: "+e2eIssuerLabel)

	// the issuing CA signs with a copied profile
	csrPEM := newCSR(t, "edge.ctl.example.com")
	signed, err := client.SignCertificate(ctx, &pb.SignCertificateRequest{
		OrgID:   orgID,
		Profile: "server",
		Request: csrPEM,
		SAN:     []string{"edge.ctl.example.com"},
		Label:   "edge-1",
	})
	require.NoError(t, err)
	crt := signed.Certificate
	t.Cleanup(func() { _, _ = provider.DeleteCertificate(ctx, org.ID.UInt64(), mustID(t, crt.ID)) })
	assert.Equal(t, issuer.SKID, crt.IKID)
	leaf, err := certutil.ParseFromPEM([]byte(crt.Pem))
	require.NoError(t, err)
	require.NoError(t, leaf.CheckSignatureFrom(issuerCert))
	assert.Equal(t, []string{"http://localhost:8880/v1/crl/" + issuer.SKID}, leaf.CRLDistributionPoints)

	// the certificate through the commands
	var certs pb.CertificatesResponse
	runJSON(&admin.CertListCmd{Org: orgID}, &certs)
	require.Len(t, certs.Certificates, 1)
	assert.Equal(t, crt.ID, certs.Certificates[0].ID)
	runJSON(&admin.CertListCmd{Org: orgID, IKID: issuer.SKID, Status: "Active", Profile: "server"}, &certs)
	require.Len(t, certs.Certificates, 1)
	runJSON(&admin.CertListCmd{Org: orgID, Status: "Revoked"}, &certs)
	assert.Empty(t, certs.Certificates)
	printed = run(&admin.CertGetCmd{Org: orgID, CertSelector: admin.CertSelector{IKID: crt.IKID, Serial: crt.SerialNumber}})
	assert.Contains(t, printed, "edge.ctl.example.com")
	assert.Contains(t, printed, "-----BEGIN CERTIFICATE-----")
	printed = run(&admin.CertRevokeCmd{OrgScope: admin.OrgScope{Org: orgID}, CertSelector: admin.CertSelector{ID: crt.ID}, Reason: "KeyCompromise", ReasonText: "ctl e2e"})
	assert.Contains(t, printed, "Key Compromise")
	runJSON(&admin.CertListCmd{Org: orgID, Status: "Revoked"}, &certs)
	require.Len(t, certs.Certificates, 1)

	// the delegated OCSP responder of the org answers for the revocation
	ocspReq, err := ocsp.CreateRequest(leaf, issuerCert, nil)
	require.NoError(t, err)
	ocspRes, err := client.SignOCSP(ctx, &pb.OCSPRequest{Der: ocspReq})
	require.NoError(t, err)
	parsed, err := ocsp.ParseResponseForCert(ocspRes.Der, leaf, issuerCert)
	require.NoError(t, err)
	assert.Equal(t, ocsp.Revoked, parsed.Status)
	assert.Equal(t, ocsp.KeyCompromise, parsed.RevocationReason)
	require.NotNil(t, parsed.Certificate, "signed by the delegated responder of the ocsp template")
	assert.NotEqual(t, issuerCert.SubjectKeyId, parsed.Certificate.SubjectKeyId)

	// the CRL through the commands
	var crls pb.CrlsResponse
	runJSON(&admin.CrlPublishCmd{Org: orgID, IKID: issuer.SKID, Force: true}, &crls)
	require.Len(t, crls.Crls, 1)
	assert.Equal(t, issuer.SKID, crls.Crls[0].IKID)
	var crl pb.CrlResponse
	runJSON(&admin.CrlGetCmd{Org: orgID, IKID: issuer.SKID}, &crl)
	require.NotNil(t, crl.Crl)
	assert.Equal(t, crls.Crls[0].Number, crl.Crl.Number)
	block, _ := pem.Decode([]byte(crl.Crl.Pem))
	require.NotNil(t, block)
	list, err := x509.ParseRevocationList(block.Bytes)
	require.NoError(t, err)
	require.NoError(t, list.CheckSignatureFrom(issuerCert))
	require.Len(t, list.RevokedCertificateEntries, 1)
	assert.Equal(t, leaf.SerialNumber, list.RevokedCertificateEntries[0].SerialNumber)
	// the due CRLs of every org and the platform, as the renewal task: none
	// may be due, since the task and the earlier runs published them
	runJSON(&admin.CrlPublishCmd{}, &crls)
	for _, c := range crls.Crls {
		assert.NotEqual(t, issuer.SKID, c.IKID, "the CRL of the org was published just now")
	}

	// the lists of the org and of the platform
	var issuers pb.IssuersResponse
	runJSON(&admin.IssuerListCmd{Org: orgID}, &issuers)
	require.Len(t, issuers.Issuers, 1)
	assert.Equal(t, issuer.ID, issuers.Issuers[0].ID)
	runJSON(&admin.IssuerListCmd{Org: orgID, Type: "Root"}, &issuers)
	assert.Empty(t, issuers.Issuers)
	var roots pb.RootsResponse
	runJSON(&admin.RootListCmd{}, &roots)
	assert.NotEmpty(t, roots.Roots, "the platform anchors")
	runJSON(&admin.RootListCmd{Org: orgID}, &roots)
	assert.Empty(t, roots.Roots, "the org has no root of its own")

	// archive and destroy
	printed = run(&admin.IssuerArchiveCmd{Org: orgID, ID: issuer.ID})
	assert.Contains(t, printed, "Archived")
	printed = run(&admin.IssuerDestroyCmd{Org: orgID, ID: issuer.ID})
	assert.Contains(t, printed, "Destroyed")
	got, err := client.GetIssuer(ctx, &pb.GetIssuerRequest{OrgID: orgID, ID: issuer.ID})
	require.NoError(t, err)
	assert.Equal(t, pb.IssuerStatus_Destroyed, got.Status)
}

// backendServer serves the CA and Admin services on a TCP listener whose
// interceptor sets the trustyca-admin identity of every call, as the
// backend listener maps the operator's client certificate
func backendServer(t *testing.T, ca pb.CAServer, adm privpb.AdminServer) string {
	t.Helper()
	lis, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)
	srv := grpc.NewServer(grpc.UnaryInterceptor(
		func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
			uid := identity.NewIdentity(e2eRole, "spiffe://trustyca/admin", "", map[string]any{}, "", "", identity.MethodCertificate)
			return handler(authctx.NewTrustyCtx(ctx, identity.NewRequestContext(uid, info.FullMethod)), req)
		}))
	pb.RegisterCAServer(srv, ca)
	privpb.RegisterAdminServer(srv, adm)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return lis.Addr().String()
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
