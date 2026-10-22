package cis_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
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
	"github.com/effective-security/trustyca/server/service/ca"
	"github.com/effective-security/trustyca/server/service/cis"
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
// CIS forwards OCSP
const (
	e2eRootLabel   = "E2E_CIS_ROOT"
	e2eRootProfile = "e2e_cis_root"
	e2ePeerProfile = "e2e_cis_peer"
	e2eRARole      = "trustyca-ra"
	e2eCISRole     = "trustyca-cis"
	e2eHTTPTimeout = 10 * time.Second
)

// TestService_EndToEnd runs the CA and the CIS of the app container over
// the configured database: a new org registers a root whose AIA, CRL and
// OCSP URLs point at the CIS listener, signs two certificates and revokes
// one, publishes the CRL, and the test follows the URLs of the issued
// certificates to the CIS as a TLS verifier would: the issuer certificate,
// the CRL, OCSP by GET and POST (the second answer from the cache), the
// JSON API, and `openssl verify -crl_check` when openssl is installed. The
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

	// the CA, called over gRPC as the RA and as the CIS
	caServer, err := gserver.Start("CISTestCA", &gserver.Config{
		ListenURLs: []string{testutils.CreateURL("http", "")},
		Services:   []string{ca.ServiceName},
	}, container, map[string]gserver.ServiceFactory{
		ca.ServiceName: ca.Factory,
	})
	require.NoError(t, err)
	t.Cleanup(caServer.Close)
	caSvc := caServer.Service(ca.ServiceName).(pb.CAServer)
	raClient := pb.NewCAClient(grpcConn(t, caSvc, e2eRARole))
	cisClient := proxypb.NewCAClient(grpcConn(t, caSvc, e2eCISRole), nil)

	// the CIS over HTTP, forwarding OCSP to the CA as the CIS identity
	cisURL := testutils.CreateURL("http", "")
	cisServer, err := gserver.Start("CISTest", &gserver.Config{
		ListenURLs: []string{cisURL},
		Services:   []string{cis.ServiceName},
	}, container, map[string]gserver.ServiceFactory{
		cis.ServiceName: func(server gserver.GServer) any {
			return func(cfg *config.Configuration, caDb db.CaReadonlyDb) error {
				svc, err := cis.New(cfg, caDb, cisClient, nil)
				if err != nil {
					return err
				}
				server.AddService(svc)
				return nil
			}
		},
	})
	require.NoError(t, err)
	t.Cleanup(cisServer.Close)
	httpClient := &http.Client{Timeout: e2eHTTPTimeout}

	// the org of the test
	ownerID := provider.NextID()
	login := &model.Login{
		ID:         ownerID,
		ExternalID: ownerID.String(),
		Name:       "E2E CIS Owner",
		Email:      ownerID.String() + "@example.com",
		Provider:   pb.IDP_Github,
	}
	_, owner, err := provider.LoginUser(ctx, login)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = provider.DeleteUserByEmail(ctx, login.Email) })
	org, err := provider.RegisterOrg(ctx, &model.Org{Name: "E2E CIS Org"}, owner.ID.UInt64())
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = provider.DeleteOrg(ctx, org.ID.UInt64()) })
	orgID := org.ID.String()

	// a root of the org whose URLs point at the CIS, and the profiles it
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
		Subject: &pb.X509Subject{CommonName: "E2E CIS Root"},
		Profile: e2eRootProfile,
		Config: &pb.IssuerConfig{
			AiaURL:     cisURL + "/v1/cert/${ISSUER_ID}",
			CrlURL:     cisURL + "/v1/crl/:ISSUER_ID",
			OcspURL:    cisURL + "/v1/ocspi/:ISSUER_ID",
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
	sign := func(cn string) (*pb.Certificate, *x509.Certificate) {
		t.Helper()
		signed, err := raClient.SignCertificate(ctx, &pb.SignCertificateRequest{
			OrgID:    orgID,
			Profile:  e2ePeerProfile,
			Request:  newCSR(t, cn),
			SAN:      []string{cn},
			Label:    "cis-" + cn,
			Metadata: map[string]string{"requester": "e2e"},
		})
		require.NoError(t, err)
		crt := signed.Certificate
		t.Cleanup(func() { _, _ = provider.DeleteCertificate(ctx, org.ID.UInt64(), mustID(t, crt.ID)) })
		x509Cert, err := certutil.ParseFromPEM([]byte(crt.Pem))
		require.NoError(t, err)
		return crt, x509Cert
	}
	good, goodCert := sign("good.example.com")
	revoked, revokedCert := sign("revoked.example.com")
	_, err = raClient.RevokeCertificate(ctx, &pb.RevokeCertificateRequest{
		OrgID:  orgID,
		ID:     revoked.ID,
		Reason: pb.ReasonCode_KeyCompromise,
	})
	require.NoError(t, err)
	published, err := raClient.PublishCrls(ctx, &pb.PublishCrlsRequest{OrgID: orgID, IKID: root.SKID})
	require.NoError(t, err)
	require.Len(t, published.Crls, 1)

	// the issued certificates point at the CIS
	skid := root.SKID
	require.Equal(t, []string{cisURL + "/v1/cert/" + skid}, goodCert.IssuingCertificateURL)
	require.Equal(t, []string{cisURL + "/v1/crl/" + skid}, goodCert.CRLDistributionPoints)
	require.Equal(t, []string{cisURL + "/v1/ocspi/" + skid}, goodCert.OCSPServer)

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
	res, body = httpPost(t, httpClient, cisURL+pb.PathForOCSP, "application/ocsp-request", revokedReq)
	require.Equal(t, http.StatusOK, res.StatusCode)
	ocspRes, err = ocsp.ParseResponseForCert(body, revokedCert, rootCert)
	require.NoError(t, err)
	assert.Equal(t, ocsp.Revoked, ocspRes.Status)
	assert.Equal(t, ocsp.KeyCompromise, ocspRes.RevocationReason)
	// a certificate of another CA is unauthorized
	other := testutils.NewTestCA(t, "Other Root", nil)
	otherReq, err := ocsp.CreateRequest(other.Issue(t, "other.example.com", time.Now().Add(-time.Hour), time.Now().Add(time.Hour)), other.Cert, nil)
	require.NoError(t, err)
	res, body = httpPost(t, httpClient, cisURL+pb.PathForOCSP, "application/ocsp-request", otherReq)
	assert.Equal(t, http.StatusNotFound, res.StatusCode)
	assert.Equal(t, ocsp.UnauthorizedErrorResponse, body)

	// the JSON API
	var info pb.IssuerInfo
	postJSON(t, httpClient, cisURL+pb.CIS_GetIssuer_FullMethodName, &pb.GetIssuerInfoRequest{IKID: skid}, &info)
	assert.Equal(t, e2eRootLabel, info.Label)
	assert.Equal(t, pb.AuthorityType_Root, info.Type)
	assert.Equal(t, pb.IssuerStatus_Active, info.Status)
	assert.Equal(t, root.Certificate, info.Certificate)
	assert.Equal(t, cisURL+"/v1/cert/"+skid, info.AiaURL)
	assert.Equal(t, cisURL+"/v1/crl/"+skid, info.CrlURL)
	assert.Equal(t, cisURL+"/v1/ocspi/"+skid, info.OcspURL)
	var cert pb.CertificateResponse
	postJSON(t, httpClient, cisURL+pb.CIS_GetCertificate_FullMethodName, &pb.GetCertificateInfoRequest{Sha256: good.Sha256}, &cert)
	assert.Equal(t, good.ID, cert.Certificate.ID)
	assert.Equal(t, good.Pem, cert.Certificate.Pem)
	assert.Empty(t, cert.Certificate.OrgID)
	assert.Empty(t, cert.Certificate.Label)
	assert.Nil(t, cert.Certificate.Metadata)
	var status pb.CertificateStatusResponse
	postJSON(t, httpClient, cisURL+pb.CIS_GetCertificateStatus_FullMethodName, &pb.GetCertificateInfoRequest{IssuerSerial: &pb.IssuerSerial{IKID: skid, SerialNumber: revoked.SerialNumber}}, &status)
	assert.Equal(t, pb.CertificateStatus_Revoked, status.Status)
	assert.Equal(t, pb.ReasonCode_KeyCompromise, status.Reason)
	assert.NotEmpty(t, status.RevokedAt)
	postJSON(t, httpClient, cisURL+pb.CIS_GetCertificateStatus_FullMethodName, &pb.GetCertificateInfoRequest{SKID: good.SKID}, &status)
	assert.Equal(t, pb.CertificateStatus_Active, status.Status)
	var crlRes pb.CrlResponse
	postJSON(t, httpClient, cisURL+pb.CIS_GetCRL_FullMethodName, &pb.GetCrlRequest{IKID: skid}, &crlRes)
	assert.Equal(t, "1", crlRes.Crl.Number)
	assert.Equal(t, published.Crls[0].ID, crlRes.Crl.ID)
	assert.Empty(t, crlRes.Crl.OrgID)
	var roots pb.RootsResponse
	postJSON(t, httpClient, cisURL+pb.CIS_GetRoots_FullMethodName, &pb.ListRootsRequest{OrgID: orgID}, &roots)
	require.Len(t, roots.Roots, 1, "the anchor of the root issuer")
	assert.Equal(t, skid, roots.Roots[0].SKID)
	postJSON(t, httpClient, cisURL+pb.CIS_GetRoots_FullMethodName, &pb.ListRootsRequest{}, &roots)
	for _, r := range roots.Roots {
		assert.Empty(t, r.OrgID, "platform anchors")
	}

	// openssl agrees with the CRL the CIS serves
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

// postJSON calls a method of the JSON API and decodes its response
func postJSON(t *testing.T, client *http.Client, u string, req any, res any) {
	t.Helper()
	body, err := json.Marshal(req)
	require.NoError(t, err)
	r, resBody := httpPost(t, client, u, header.ApplicationJSON, body)
	require.Equal(t, http.StatusOK, r.StatusCode, string(resBody))
	require.NoError(t, json.Unmarshal(resBody, res), string(resBody))
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
