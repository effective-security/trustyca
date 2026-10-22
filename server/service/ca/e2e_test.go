package ca_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/effective-security/porto/gserver"
	"github.com/effective-security/porto/xhttp/identity"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/authctx"
	"github.com/effective-security/trustyca/internal/config"
	"github.com/effective-security/trustyca/internal/db"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/server/appcontainer"
	"github.com/effective-security/trustyca/server/service/ca"
	"github.com/effective-security/trustyca/tests/testutils"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xpki/certutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// The labels of the CA the end-to-end test creates in its org
const (
	e2eRootLabel   = "E2E_ROOT"
	e2eRootProfile = "e2e_root"
	e2ePeerProfile = "e2e_peer"
	// e2eRole is the service identity of the RA, which names the org of
	// every request
	e2eRole = "trustyca-ra"
)

// TestService_EndToEnd runs the CA service of the app container over the
// configured database, with the platform issuer of ca.bootstrap_config, and
// calls it over gRPC as the RA: it registers a root of its own in a new
// org, signs, reads, lists, relabels and revokes a certificate, checks the
// revocation status through OCSP, publishes and reads the CRL of the root,
// and asks the bootstrap issuer for the status of a certificate it issued
// outside the service. The data
// protection seed is the environment's, as for every process that uses the
// dev DB: the platform issuer in it is wrapped under that seed.
func TestService_EndToEnd(t *testing.T) {
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

	server, err := gserver.Start("CATest", &gserver.Config{
		ListenURLs: []string{testutils.CreateURL("http", "")},
		Services:   []string{ca.ServiceName},
	}, container, map[string]gserver.ServiceFactory{
		ca.ServiceName: ca.Factory,
	})
	require.NoError(t, err)
	t.Cleanup(server.Close)
	client := grpcClient(t, server.Service(ca.ServiceName).(pb.CAServer))

	// the org of the test
	ownerID := provider.NextID()
	login := &model.Login{
		ID:         ownerID,
		ExternalID: ownerID.String(),
		Name:       "E2E Owner",
		Email:      ownerID.String() + "@example.com",
		Provider:   pb.IDP_Github,
	}
	_, owner, err := provider.LoginUser(ctx, login)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = provider.DeleteUserByEmail(ctx, login.Email) })
	org, err := provider.RegisterOrg(ctx, &model.Org{Name: "E2E Org"}, owner.ID.UInt64())
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = provider.DeleteOrg(ctx, org.ID.UInt64()) })
	orgID := org.ID.String()

	// the bootstrap issuer answers for the certificates it issued: the dev
	// client certificate was issued outside the service, so it is unknown
	clientCert := readCert(t, "trustyca_client.pem")
	l2Cert := readCert(t, "trustyca_l2_ca.pem")
	ocspReq, err := ocsp.CreateRequest(clientCert, l2Cert, nil)
	require.NoError(t, err)
	ocspRes, err := client.SignOCSP(ctx, &pb.OCSPRequest{Der: ocspReq})
	require.NoError(t, err)
	parsed, err := ocsp.ParseResponseForCert(ocspRes.Der, clientCert, l2Cert)
	require.NoError(t, err)
	assert.Equal(t, ocsp.Unknown, parsed.Status, "the bootstrap issuer never registered the dev client certificate")

	// a root of the org and the profiles it serves
	rootProfile, err := client.RegisterProfile(ctx, &pb.RegisterProfileRequest{
		OrgID: orgID,
		Profile: &pb.CertProfile{
			Label:       e2eRootProfile,
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
	root, err := client.RegisterIssuer(ctx, &pb.RegisterIssuerRequest{
		OrgID:   orgID,
		Label:   e2eRootLabel,
		Type:    pb.AuthorityType_Root,
		Subject: &pb.X509Subject{CommonName: "E2E Root"},
		Profile: e2eRootProfile,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		// the key of the root is destroyed in its provider through the
		// service, then the rows are removed
		_, _ = client.UpdateIssuer(ctx, &pb.UpdateIssuerRequest{OrgID: orgID, ID: root.ID, Status: pb.IssuerStatus_Archived})
		_, _ = client.UpdateIssuer(ctx, &pb.UpdateIssuerRequest{OrgID: orgID, ID: root.ID, Status: pb.IssuerStatus_Destroyed})
		roots, err := client.ListRoots(ctx, &pb.ListRootsRequest{OrgID: orgID})
		if err == nil {
			for _, r := range roots.Roots {
				_, _ = provider.DeleteRoot(ctx, org.ID.UInt64(), mustID(t, r.ID))
			}
		}
		_, _ = provider.DeleteIssuer(ctx, org.ID.UInt64(), mustID(t, root.ID))
	})
	assert.Equal(t, pb.IssuerStatus_Active, root.Status)
	rootCert, err := certutil.ParseFromPEM([]byte(root.Certificate))
	require.NoError(t, err)
	peerProfile, err := client.RegisterProfile(ctx, &pb.RegisterProfileRequest{
		OrgID: orgID,
		Profile: &pb.CertProfile{
			Label:             e2ePeerProfile,
			IssuerLabel:       e2eRootLabel,
			Expiry:            "168h",
			Backdate:          "30m",
			Usages:            []string{"signing", "key encipherment", "server auth"},
			AllowedExtensions: []string{"2.5.29.17"},
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = provider.DeleteProfile(ctx, org.ID.UInt64(), mustID(t, peerProfile.ID)) })

	// sign
	csrPEM := newCSR(t, "e2e.example.com")
	signed, err := client.SignCertificate(ctx, &pb.SignCertificateRequest{
		OrgID:    orgID,
		Profile:  e2ePeerProfile,
		Request:  csrPEM,
		SAN:      []string{"e2e.example.com"},
		Label:    "edge-1",
		Metadata: map[string]string{"requester": "e2e"},
	})
	require.NoError(t, err)
	crt := signed.Certificate
	t.Cleanup(func() { _, _ = provider.DeleteCertificate(ctx, org.ID.UInt64(), mustID(t, crt.ID)) })
	assert.Equal(t, orgID, crt.OrgID)
	assert.Equal(t, root.SKID, crt.IKID)
	assert.Equal(t, e2ePeerProfile, crt.Profile)
	assert.Equal(t, pb.CertificateStatus_Active, crt.Status)
	assert.Equal(t, "edge-1", crt.Label)
	x509Cert, err := certutil.ParseFromPEM([]byte(crt.Pem))
	require.NoError(t, err)
	assert.Equal(t, []string{"e2e.example.com"}, x509Cert.DNSNames)
	require.NoError(t, x509Cert.CheckSignatureFrom(rootCert), "signed by the root of the org")

	// get, by every selector
	got, err := client.GetCertificate(ctx, &pb.GetCertificateRequest{OrgID: orgID, ID: crt.ID})
	require.NoError(t, err)
	assert.Equal(t, crt.Sha256, got.Certificate.Sha256)
	got, err = client.GetCertificate(ctx, &pb.GetCertificateRequest{OrgID: orgID, SKID: crt.SKID})
	require.NoError(t, err)
	assert.Equal(t, crt.ID, got.Certificate.ID)
	got, err = client.GetCertificate(ctx, &pb.GetCertificateRequest{OrgID: orgID, Sha256: crt.Sha256})
	require.NoError(t, err)
	assert.Equal(t, crt.ID, got.Certificate.ID)
	got, err = client.GetCertificate(ctx, &pb.GetCertificateRequest{OrgID: orgID, IssuerSerial: &pb.IssuerSerial{IKID: crt.IKID, SerialNumber: crt.SerialNumber}})
	require.NoError(t, err)
	assert.Equal(t, crt.ID, got.Certificate.ID)
	_, err = client.GetCertificate(ctx, &pb.GetCertificateRequest{OrgID: orgID, ID: "1"})
	requireStatus(t, err, codes.NotFound, "certificate not found")

	// list
	list, err := client.ListCertificates(ctx, &pb.ListCertificatesRequest{OrgID: orgID, IKID: root.SKID, Status: pb.CertificateStatus_Active})
	require.NoError(t, err)
	require.Len(t, list.Certificates, 1)
	assert.Equal(t, crt.ID, list.Certificates[0].ID)
	assert.Nil(t, list.NextPage)
	list, err = client.ListCertificates(ctx, &pb.ListCertificatesRequest{OrgID: orgID, Status: pb.CertificateStatus_Revoked})
	require.NoError(t, err)
	assert.Empty(t, list.Certificates)

	// relabel
	upd, err := client.UpdateCertificateLabel(ctx, &pb.UpdateCertificateLabelRequest{OrgID: orgID, ID: crt.ID, Label: "edge-2"})
	require.NoError(t, err)
	assert.Equal(t, "edge-2", upd.Certificate.Label)
	assert.Equal(t, map[string]string{"requester": "e2e"}, upd.Certificate.Metadata, "kept")

	// the status is good before the revocation
	ocspReq, err = ocsp.CreateRequest(x509Cert, rootCert, nil)
	require.NoError(t, err)
	ocspRes, err = client.SignOCSP(ctx, &pb.OCSPRequest{Der: ocspReq})
	require.NoError(t, err)
	parsed, err = ocsp.ParseResponseForCert(ocspRes.Der, x509Cert, rootCert)
	require.NoError(t, err)
	assert.Equal(t, ocsp.Good, parsed.Status)

	// revoke: the certificate, its revocation and OCSP agree
	revoked, err := client.RevokeCertificate(ctx, &pb.RevokeCertificateRequest{
		OrgID:      orgID,
		ID:         crt.ID,
		Reason:     pb.ReasonCode_KeyCompromise,
		ReasonText: "e2e",
	})
	require.NoError(t, err)
	assert.Equal(t, crt.ID, revoked.Revoked.Certificate.ID)
	assert.Equal(t, pb.CertificateStatus_Revoked, revoked.Revoked.Certificate.Status)
	assert.Equal(t, pb.ReasonCode_KeyCompromise, revoked.Revoked.Reason)
	assert.Equal(t, "edge-2", revoked.Revoked.Certificate.Label)
	_, err = client.RevokeCertificate(ctx, &pb.RevokeCertificateRequest{OrgID: orgID, ID: crt.ID})
	requireStatus(t, err, codes.FailedPrecondition, "certificate is already revoked")
	got, err = client.GetCertificate(ctx, &pb.GetCertificateRequest{OrgID: orgID, ID: crt.ID})
	require.NoError(t, err)
	assert.Equal(t, pb.CertificateStatus_Revoked, got.Certificate.Status)
	revokedList, err := client.ListRevokedCertificates(ctx, &pb.ListRevokedCertificatesRequest{OrgID: orgID, IKID: root.SKID})
	require.NoError(t, err)
	require.Len(t, revokedList.RevokedCertificates, 1)
	assert.Equal(t, crt.ID, revokedList.RevokedCertificates[0].Certificate.ID)
	assert.Equal(t, "e2e", revokedList.RevokedCertificates[0].ReasonText)
	ocspRes, err = client.SignOCSP(ctx, &pb.OCSPRequest{Der: ocspReq})
	require.NoError(t, err)
	parsed, err = ocsp.ParseResponseForCert(ocspRes.Der, x509Cert, rootCert)
	require.NoError(t, err)
	assert.Equal(t, ocsp.Revoked, parsed.Status)
	assert.Equal(t, ocsp.KeyCompromise, parsed.RevocationReason)
	assert.WithinDuration(t, time.Now(), parsed.RevokedAt, time.Minute)

	// the CRL of the root: none until it is published, then the revoked
	// certificate is listed with its reason, signed by the root
	_, err = client.GetCRL(ctx, &pb.GetCrlRequest{OrgID: orgID, IKID: root.SKID})
	requireStatus(t, err, codes.NotFound, "CRL not found")
	published, err := client.PublishCrls(ctx, &pb.PublishCrlsRequest{OrgID: orgID, IKID: root.SKID})
	require.NoError(t, err)
	require.Len(t, published.Crls, 1)
	assert.Equal(t, "1", published.Crls[0].Number)
	assert.Equal(t, root.SKID, published.Crls[0].IKID)
	assert.Equal(t, root.ID, published.Crls[0].IssuerID)
	assert.Equal(t, orgID, published.Crls[0].OrgID)
	crlRes, err := client.GetCRL(ctx, &pb.GetCrlRequest{OrgID: orgID, IKID: root.SKID})
	require.NoError(t, err)
	assert.Equal(t, published.Crls[0].ID, crlRes.Crl.ID)
	assert.Equal(t, published.Crls[0].Pem, crlRes.Crl.Pem)
	block, _ := pem.Decode([]byte(crlRes.Crl.Pem))
	require.NotNil(t, block)
	crl, err := x509.ParseRevocationList(block.Bytes)
	require.NoError(t, err)
	require.NoError(t, crl.CheckSignatureFrom(rootCert))
	assert.EqualValues(t, 1, crl.Number.Int64())
	assert.True(t, crl.NextUpdate.After(crl.ThisUpdate))
	require.Len(t, crl.RevokedCertificateEntries, 1)
	assert.Equal(t, 0, x509Cert.SerialNumber.Cmp(crl.RevokedCertificateEntries[0].SerialNumber))
	assert.Equal(t, ocsp.KeyCompromise, crl.RevokedCertificateEntries[0].ReasonCode)
	assert.WithinDuration(t, time.Now(), crl.RevokedCertificateEntries[0].RevocationTime, time.Minute)
	gotRoot, err := client.GetIssuer(ctx, &pb.GetIssuerRequest{OrgID: orgID, ID: root.ID})
	require.NoError(t, err)
	assert.Equal(t, "1", gotRoot.CrlNumber, "the issuer records the number")

	// a fresh CRL is not published again unless forced; the number grows
	published, err = client.PublishCrls(ctx, &pb.PublishCrlsRequest{OrgID: orgID, IKID: root.SKID})
	require.NoError(t, err)
	assert.Empty(t, published.Crls)
	published, err = client.PublishCrls(ctx, &pb.PublishCrlsRequest{OrgID: orgID, Force: true})
	require.NoError(t, err)
	require.Len(t, published.Crls, 1, "every issuer of the org")
	assert.Equal(t, "2", published.Crls[0].Number)
	assert.Equal(t, root.SKID, published.Crls[0].IKID)
	_, err = client.PublishCrls(ctx, &pb.PublishCrlsRequest{OrgID: orgID, IKID: certutil.GetSubjectKeyID(l2Cert)})
	requireStatus(t, err, codes.NotFound, "issuer not found", "the platform issuer is not the org's")
}

// grpcClient serves the CA over an in-memory gRPC connection, as the RA
// calls it: the auth interceptor sets the service identity of the caller
func grpcClient(t *testing.T, svc pb.CAServer) pb.CAClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer(grpc.UnaryInterceptor(
		func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
			uid := identity.NewIdentity(e2eRole, "spiffe://trustyca/ra", "", map[string]any{}, "", "", identity.MethodCertificate)
			return handler(authctx.NewTrustyCtx(ctx, identity.NewRequestContext(uid, info.FullMethod)), req)
		}))
	pb.RegisterCAServer(srv, svc)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return pb.NewCAClient(conn)
}

// requireStatus asserts the gRPC status of an error
func requireStatus(t *testing.T, err error, code codes.Code, msg string, msgAndArgs ...any) {
	t.Helper()
	st, ok := status.FromError(err)
	require.True(t, ok, "%v", err)
	assert.Equal(t, code, st.Code(), msgAndArgs...)
	assert.Equal(t, msg, st.Message(), msgAndArgs...)
}

// readCert reads a certificate of the dev PKI from the home directory
func readCert(t *testing.T, name string) *x509.Certificate {
	t.Helper()
	home, err := os.UserHomeDir()
	require.NoError(t, err)
	crt, err := certutil.LoadFromPEM(filepath.Join(home, ".trustyca", "certs", name))
	require.NoError(t, err)
	return crt
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
