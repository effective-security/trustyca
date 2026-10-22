package aia_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/effective-security/porto/gserver"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/identity"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/api/pb/proxypb"
	"github.com/effective-security/trustyca/internal/authctx"
	"github.com/effective-security/trustyca/internal/config"
	"github.com/effective-security/trustyca/internal/db"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/server/appcontainer"
	"github.com/effective-security/trustyca/server/service/aia"
	"github.com/effective-security/trustyca/server/service/ca"
	"github.com/effective-security/trustyca/tests/testutils"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xpki/certutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

// The labels of the CA the end-to-end test creates in its org, and the
// service identities it calls the CA with: the RA registers and signs, the
// AIA forwards OCSP
const (
	e2eRootLabel   = "E2E_AIA_ROOT"
	e2eRootProfile = "e2e_aia_root"
	e2ePeerProfile = "e2e_aia_peer"
	e2eRARole      = "trustyca-ra"
	e2eAIARole     = "trustyca-aia"
	e2eHTTPTimeout = 10 * time.Second
)

// TestService_EndToEnd runs the CA and the AIA of the app container over
// the configured database: a new org registers a root whose AIA, CRL and
// OCSP URLs point at the plain HTTP listener of the AIA, signs two
// certificates and revokes one, publishes the CRL, and the test follows the
// URLs of the issued certificates as a TLS verifier would: the issuer
// certificate, the CRL, OCSP by GET and POST (the second answer from the
// cache), and `openssl verify -crl_check` when openssl is installed. The
// data protection seed is the environment's, as for every process that
// uses the dev DB.
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

	// the CA, called over gRPC as the RA and as the AIA
	caServer, err := gserver.Start("AIATestCA", &gserver.Config{
		ListenURLs: []string{testutils.CreateURL("http", "")},
		Services:   []string{ca.ServiceName},
	}, container, map[string]gserver.ServiceFactory{
		ca.ServiceName: ca.Factory,
	})
	require.NoError(t, err)
	t.Cleanup(caServer.Close)
	caSvc := caServer.Service(ca.ServiceName).(pb.CAServer)
	raClient := pb.NewCAClient(grpcConn(t, caSvc, e2eRARole))
	aiaClient := proxypb.NewCAClient(grpcConn(t, caSvc, e2eAIARole), nil)

	// the AIA over plain HTTP, forwarding OCSP to the CA as the AIA identity
	aiaURL := testutils.CreateURL("http", "")
	aiaServer, err := gserver.Start("AIATest", &gserver.Config{
		ListenURLs: []string{aiaURL},
		Services:   []string{aia.ServiceName},
	}, container, map[string]gserver.ServiceFactory{
		aia.ServiceName: func(server gserver.GServer) any {
			return func(cfg *config.Configuration, caDb db.CaReadonlyDb) error {
				svc, err := aia.New(cfg, caDb, aiaClient, nil)
				if err != nil {
					return err
				}
				server.AddService(svc)
				return nil
			}
		},
	})
	require.NoError(t, err)
	t.Cleanup(aiaServer.Close)
	httpClient := &http.Client{Timeout: e2eHTTPTimeout}

	// the org of the test
	ownerID := provider.NextID()
	login := &model.Login{
		ID:         ownerID,
		ExternalID: ownerID.String(),
		Name:       "E2E AIA Owner",
		Email:      ownerID.String() + "@example.com",
		Provider:   pb.IDP_Github,
	}
	_, owner, err := provider.LoginUser(ctx, login)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = provider.DeleteUserByEmail(ctx, login.Email) })
	org, err := provider.RegisterOrg(ctx, &model.Org{Name: "E2E AIA Org"}, owner.ID.UInt64())
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = provider.DeleteOrg(ctx, org.ID.UInt64()) })
	orgID := org.ID.String()

	// a root of the org whose URLs point at the AIA, and the profiles it
	// serves
	rootProfile, err := raClient.RegisterProfile(ctx, &pb.RegisterProfileRequest{
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
	root, err := raClient.RegisterIssuer(ctx, &pb.RegisterIssuerRequest{
		OrgID:   orgID,
		Label:   e2eRootLabel,
		Type:    pb.AuthorityType_Root,
		Subject: &pb.X509Subject{CommonName: "E2E AIA Root"},
		Profile: e2eRootProfile,
		Config: &pb.IssuerConfig{
			AiaURL:     aiaURL + "/v1/cert/${ISSUER_ID}",
			CrlURL:     aiaURL + "/v1/crl/:ISSUER_ID",
			OcspURL:    aiaURL + "/v1/ocspi/:ISSUER_ID",
			CrlExpiry:  "48h",
			CrlRenewal: "12h",
			OcspExpiry: "1h",
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		// the key of the root is destroyed in its provider through the
		// service, then the rows are removed
		_, _ = raClient.UpdateIssuer(ctx, &pb.UpdateIssuerRequest{OrgID: orgID, ID: root.ID, Status: pb.IssuerStatus_Archived})
		_, _ = raClient.UpdateIssuer(ctx, &pb.UpdateIssuerRequest{OrgID: orgID, ID: root.ID, Status: pb.IssuerStatus_Destroyed})
		roots, err := raClient.ListRoots(ctx, &pb.ListRootsRequest{OrgID: orgID})
		if err == nil {
			for _, r := range roots.Roots {
				_, _ = provider.DeleteRoot(ctx, org.ID.UInt64(), mustID(t, r.ID))
			}
		}
		_, _ = provider.DeleteIssuer(ctx, org.ID.UInt64(), mustID(t, root.ID))
	})
	rootCert, err := certutil.ParseFromPEM([]byte(root.Certificate))
	require.NoError(t, err)
	peerProfile, err := raClient.RegisterProfile(ctx, &pb.RegisterProfileRequest{
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

	// two certificates, one of which is revoked
	sign := func(cn string) *x509.Certificate {
		t.Helper()
		signed, err := raClient.SignCertificate(ctx, &pb.SignCertificateRequest{
			OrgID:    orgID,
			Profile:  e2ePeerProfile,
			Request:  newCSR(t, cn),
			SAN:      []string{cn},
			Label:    "aia-" + cn,
			Metadata: map[string]string{"requester": "e2e"},
		})
		require.NoError(t, err)
		crt := signed.Certificate
		t.Cleanup(func() { _, _ = provider.DeleteCertificate(ctx, org.ID.UInt64(), mustID(t, crt.ID)) })
		x509Cert, err := certutil.ParseFromPEM([]byte(crt.Pem))
		require.NoError(t, err)
		return x509Cert
	}
	goodCert := sign("good.example.com")
	revokedCert := sign("revoked.example.com")
	_, err = raClient.RevokeCertificate(ctx, &pb.RevokeCertificateRequest{
		OrgID:        orgID,
		IssuerSerial: &pb.IssuerSerial{IKID: root.SKID, SerialNumber: revokedCert.SerialNumber.String()},
		Reason:       pb.ReasonCode_KeyCompromise,
	})
	require.NoError(t, err)
	published, err := raClient.PublishCrls(ctx, &pb.PublishCrlsRequest{OrgID: orgID, IKID: root.SKID})
	require.NoError(t, err)
	require.Len(t, published.Crls, 1)

	// the issued certificates point at the AIA
	skid := root.SKID
	require.Equal(t, []string{aiaURL + "/v1/cert/" + skid}, goodCert.IssuingCertificateURL)
	require.Equal(t, []string{aiaURL + "/v1/crl/" + skid}, goodCert.CRLDistributionPoints)
	require.Equal(t, []string{aiaURL + "/v1/ocspi/" + skid}, goodCert.OCSPServer)

	// AIA caIssuers: the certificate of the root
	res, body := httpGet(t, httpClient, goodCert.IssuingCertificateURL[0], nil)
	require.Equal(t, http.StatusOK, res.StatusCode, string(body))
	assert.Equal(t, certContentType, res.Header.Get(header.ContentType))
	assert.Equal(t, rootCert.Raw, body)
	assert.Contains(t, res.Header.Get(header.CacheControl), "max-age=")
	etag := res.Header.Get("ETag")
	require.NotEmpty(t, etag)
	res, _ = httpGet(t, httpClient, goodCert.IssuingCertificateURL[0], map[string]string{"If-None-Match": etag})
	assert.Equal(t, http.StatusNotModified, res.StatusCode)

	// CDP: the CRL of the root, with the revoked certificate
	res, body = httpGet(t, httpClient, goodCert.CRLDistributionPoints[0], nil)
	require.Equal(t, http.StatusOK, res.StatusCode, string(body))
	assert.Equal(t, crlContentType, res.Header.Get(header.ContentType))
	crl, err := x509.ParseRevocationList(body)
	require.NoError(t, err)
	require.NoError(t, crl.CheckSignatureFrom(rootCert))
	assert.EqualValues(t, 1, crl.Number.Int64())
	require.Len(t, crl.RevokedCertificateEntries, 1)
	assert.Equal(t, 0, revokedCert.SerialNumber.Cmp(crl.RevokedCertificateEntries[0].SerialNumber))
	assert.Equal(t, ocsp.KeyCompromise, crl.RevokedCertificateEntries[0].ReasonCode)
	assert.Equal(t, crl.NextUpdate.UTC().Format(http.TimeFormat), res.Header.Get("Expires"))
	crlDER := body

	// OCSP: by POST at the URL of the certificate, and by GET with the
	// request in the path; the second answer comes from the cache
	goodReq, err := ocsp.CreateRequest(goodCert, rootCert, nil)
	require.NoError(t, err)
	res, body = httpPost(t, httpClient, goodCert.OCSPServer[0], "application/ocsp-request", goodReq)
	require.Equal(t, http.StatusOK, res.StatusCode)
	assert.Equal(t, ocspContentType, res.Header.Get(header.ContentType))
	ocspRes, err := ocsp.ParseResponseForCert(body, goodCert, rootCert)
	require.NoError(t, err)
	assert.Equal(t, ocsp.Good, ocspRes.Status)
	assert.Contains(t, res.Header.Get(header.CacheControl), "max-age=")
	etag = res.Header.Get("ETag")
	require.NotEmpty(t, etag)
	first := body
	getURL := goodCert.OCSPServer[0] + "/" + url.PathEscape(base64.StdEncoding.EncodeToString(goodReq))
	res, body = httpGet(t, httpClient, getURL, nil)
	require.Equal(t, http.StatusOK, res.StatusCode)
	assert.Equal(t, first, body, "from the cache")
	assert.Equal(t, etag, res.Header.Get("ETag"))
	res, _ = httpGet(t, httpClient, getURL, map[string]string{"If-None-Match": etag})
	assert.Equal(t, http.StatusNotModified, res.StatusCode)
	revokedReq, err := ocsp.CreateRequest(revokedCert, rootCert, nil)
	require.NoError(t, err)
	res, body = httpPost(t, httpClient, aiaURL+pb.PathForOCSP, "application/ocsp-request", revokedReq)
	require.Equal(t, http.StatusOK, res.StatusCode)
	ocspRes, err = ocsp.ParseResponseForCert(body, revokedCert, rootCert)
	require.NoError(t, err)
	assert.Equal(t, ocsp.Revoked, ocspRes.Status)
	assert.Equal(t, ocsp.KeyCompromise, ocspRes.RevocationReason)
	// a certificate of another CA is unauthorized
	other := testutils.NewTestCA(t, "Other Root", nil)
	otherReq, err := ocsp.CreateRequest(other.Issue(t, "other.example.com", time.Now().Add(-time.Hour), time.Now().Add(time.Hour)), other.Cert, nil)
	require.NoError(t, err)
	res, body = httpPost(t, httpClient, aiaURL+pb.PathForOCSP, "application/ocsp-request", otherReq)
	assert.Equal(t, http.StatusNotFound, res.StatusCode)
	assert.Equal(t, ocsp.UnauthorizedErrorResponse, body)

	// the JSON API is not served by the AIA
	res, _ = httpPost(t, httpClient, aiaURL+pb.CIS_GetRoots_FullMethodName, header.ApplicationJSON, []byte("{}"))
	assert.Equal(t, http.StatusNotFound, res.StatusCode)

	// openssl agrees with the CRL the AIA serves
	opensslVerify(t, rootCert, crlDER, goodCert, revokedCert)
}

// opensslVerify checks the certificates against the CRL with openssl, when
// it is installed: the good one verifies and the revoked one does not
func opensslVerify(t *testing.T, root *x509.Certificate, crlDER []byte, good, revoked *x509.Certificate) {
	t.Helper()
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Log("openssl is not installed: skipping the CRL check")
		return
	}
	dir := t.TempDir()
	write := func(name string, block *pem.Block) string {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(block), 0o600))
		return path
	}
	rootPath := write("root.pem", &pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})
	crlPath := write("crl.pem", &pem.Block{Type: "X509 CRL", Bytes: crlDER})
	goodPath := write("good.pem", &pem.Block{Type: "CERTIFICATE", Bytes: good.Raw})
	revokedPath := write("revoked.pem", &pem.Block{Type: "CERTIFICATE", Bytes: revoked.Raw})

	ctx, cancel := context.WithTimeout(context.Background(), e2eHTTPTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, openssl, "verify", "-crl_check", "-CAfile", rootPath, "-CRLfile", crlPath, goodPath).CombinedOutput()
	require.NoError(t, err, string(out))
	assert.Contains(t, string(out), ": OK")
	out, err = exec.CommandContext(ctx, openssl, "verify", "-crl_check", "-CAfile", rootPath, "-CRLfile", crlPath, revokedPath).CombinedOutput()
	require.Error(t, err, string(out))
	assert.Contains(t, strings.ToLower(string(out)), "certificate revoked")
}

// grpcConn serves the CA over an in-memory gRPC connection as a service
// identity: the auth interceptor sets the role of the caller
func grpcConn(t *testing.T, svc pb.CAServer, role string) *grpc.ClientConn {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer(grpc.UnaryInterceptor(
		func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
			uid := identity.NewIdentity(role, "spiffe://trustyca/"+strings.TrimPrefix(role, "trustyca-"), "", map[string]any{}, "", "", identity.MethodCertificate)
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
	return conn
}

// httpGet returns the response and body of a GET with the headers
func httpGet(t *testing.T, client *http.Client, u string, headers map[string]string) (*http.Response, []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), e2eHTTPTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	require.NoError(t, err)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := client.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	return res, body
}

// httpPost returns the response and body of a POST of the body
func httpPost(t *testing.T, client *http.Client, u, contentType string, body []byte) (*http.Response, []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), e2eHTTPTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set(header.ContentType, contentType)
	res, err := client.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	resBody, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	return res, resBody
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
