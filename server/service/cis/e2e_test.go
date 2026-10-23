package cis_test

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
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/effective-security/trustyca/server/service/backend"

	"github.com/effective-security/porto/gserver"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/identity"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/authctx"
	"github.com/effective-security/trustyca/internal/config"
	"github.com/effective-security/trustyca/internal/db"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/server/appcontainer"
	"github.com/effective-security/trustyca/server/service/ca"
	"github.com/effective-security/trustyca/server/service/cis"
	"github.com/effective-security/trustyca/tests/testutils"
	"github.com/effective-security/xdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

// The labels of the CA the end-to-end test creates in its org, the
// identity it calls the CA with, and the AIA listener its URL templates
// name (the CIS reports the URLs, the aia service serves them)
const (
	e2eRootLabel   = "E2E_CIS_ROOT"
	e2eRootProfile = "e2e_cis_root"
	e2ePeerProfile = "e2e_cis_peer"
	e2eRARole      = "trustyca-ra"
	e2eAiaURL      = "http://aia.test:8888"
	e2eHTTPTimeout = 10 * time.Second
)

// TestService_EndToEnd runs the CA and the CIS of the app container over
// the configured database: a new org registers a root, signs two
// certificates and revokes one, publishes the CRL, and the test reads them
// back through the JSON API of the CIS over HTTP: the issuer with its
// expanded URLs, the certificate and its status, the CRL and the trust
// anchors of the org and of the platform. The data protection seed is the
// environment's, as for every process that uses the dev DB.
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

	// the CA, called over gRPC as the RA
	caServer, err := gserver.Start("CISTestCA", &gserver.Config{
		ListenURLs: []string{testutils.CreateURL("http", "")},
		Services:   []string{ca.ServiceName, backend.ServiceName},
	}, container, map[string]gserver.ServiceFactory{
		ca.ServiceName:      ca.Factory,
		backend.ServiceName: backend.Factory,
	})
	require.NoError(t, err)
	t.Cleanup(caServer.Close)
	caSvc := caServer.Service(ca.ServiceName).(pb.CAServer)
	raClient := pb.NewCAClient(grpcConn(t, caSvc, e2eRARole))

	// the CIS over HTTP, built by its factory from the container
	cisURL := testutils.CreateURL("http", "")
	cisServer, err := gserver.Start("CISTest", &gserver.Config{
		ListenURLs: []string{cisURL},
		Services:   []string{cis.ServiceName},
	}, container, map[string]gserver.ServiceFactory{
		cis.ServiceName: cis.Factory,
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

	// a root of the org and the profiles it serves
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
			AiaURL:     e2eAiaURL + "/v1/cert/${ISSUER_ID}",
			CrlURL:     e2eAiaURL + "/v1/crl/:ISSUER_ID",
			OcspURL:    e2eAiaURL + "/v1/ocspi/:ISSUER_ID",
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
	sign := func(cn string) *pb.Certificate {
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
		return crt
	}
	good := sign("good.example.com")
	revoked := sign("revoked.example.com")
	_, err = raClient.RevokeCertificate(ctx, &pb.RevokeCertificateRequest{
		OrgID:  orgID,
		ID:     revoked.ID,
		Reason: pb.ReasonCode_KeyCompromise,
	})
	require.NoError(t, err)
	published, err := raClient.PublishCrls(ctx, &pb.PublishCrlsRequest{OrgID: orgID, IKID: root.SKID})
	require.NoError(t, err)
	require.Len(t, published.Crls, 1)

	// the issuer, with the URL templates expanded to the AIA routes
	skid := root.SKID
	var info pb.IssuerInfo
	postJSON(t, httpClient, cisURL+pb.CIS_GetIssuer_FullMethodName, &pb.GetIssuerInfoRequest{IKID: skid}, &info)
	assert.Equal(t, e2eRootLabel, info.Label)
	assert.Equal(t, pb.AuthorityType_Root, info.Type)
	assert.Equal(t, pb.IssuerStatus_Active, info.Status)
	assert.Equal(t, root.Certificate, info.Certificate)
	assert.Equal(t, e2eAiaURL+"/v1/cert/"+skid, info.AiaURL)
	assert.Equal(t, e2eAiaURL+"/v1/crl/"+skid, info.CrlURL)
	assert.Equal(t, e2eAiaURL+"/v1/ocspi/"+skid, info.OcspURL)

	// the certificate without its tenancy and client-owned fields
	var cert pb.CertificateResponse
	postJSON(t, httpClient, cisURL+pb.CIS_GetCertificate_FullMethodName, &pb.GetCertificateInfoRequest{Sha256: good.Sha256}, &cert)
	assert.Equal(t, good.ID, cert.Certificate.ID)
	assert.Equal(t, good.Pem, cert.Certificate.Pem)
	assert.Empty(t, cert.Certificate.OrgID)
	assert.Empty(t, cert.Certificate.Label)
	assert.Nil(t, cert.Certificate.Metadata)

	// the status of the revoked and of the good certificate
	var status pb.CertificateStatusResponse
	postJSON(t, httpClient, cisURL+pb.CIS_GetCertificateStatus_FullMethodName, &pb.GetCertificateInfoRequest{IssuerSerial: &pb.IssuerSerial{IKID: skid, SerialNumber: revoked.SerialNumber}}, &status)
	assert.Equal(t, pb.CertificateStatus_Revoked, status.Status)
	assert.Equal(t, pb.ReasonCode_KeyCompromise, status.Reason)
	assert.NotEmpty(t, status.RevokedAt)
	postJSON(t, httpClient, cisURL+pb.CIS_GetCertificateStatus_FullMethodName, &pb.GetCertificateInfoRequest{SKID: good.SKID}, &status)
	assert.Equal(t, pb.CertificateStatus_Active, status.Status)

	// the published CRL, with the revoked certificate
	var crlRes pb.CrlResponse
	postJSON(t, httpClient, cisURL+pb.CIS_GetCRL_FullMethodName, &pb.GetCrlRequest{IKID: skid}, &crlRes)
	assert.Equal(t, "1", crlRes.Crl.Number)
	assert.Equal(t, published.Crls[0].ID, crlRes.Crl.ID)
	assert.Empty(t, crlRes.Crl.OrgID)
	block, _ := pem.Decode([]byte(crlRes.Crl.Pem))
	require.NotNil(t, block)
	crl, err := x509.ParseRevocationList(block.Bytes)
	require.NoError(t, err)
	require.Len(t, crl.RevokedCertificateEntries, 1)
	assert.Equal(t, revoked.SerialNumber, crl.RevokedCertificateEntries[0].SerialNumber.String())

	// the trust anchors of the org, and of the platform
	var roots pb.RootsResponse
	postJSON(t, httpClient, cisURL+pb.CIS_GetRoots_FullMethodName, &pb.ListRootsRequest{OrgID: orgID}, &roots)
	require.Len(t, roots.Roots, 1, "the anchor of the root issuer")
	assert.Equal(t, skid, roots.Roots[0].SKID)
	postJSON(t, httpClient, cisURL+pb.CIS_GetRoots_FullMethodName, &pb.ListRootsRequest{}, &roots)
	for _, r := range roots.Roots {
		assert.Empty(t, r.OrgID, "platform anchors")
	}

	// the binary routes are the AIA's: the CIS listener does not serve them
	res, _ := httpGet(t, httpClient, cisURL+"/v1/cert/"+skid)
	assert.Equal(t, http.StatusNotFound, res.StatusCode)
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

// httpGet returns the response and body of a GET
func httpGet(t *testing.T, client *http.Client, u string) (*http.Response, []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), e2eHTTPTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	require.NoError(t, err)
	res, err := client.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	return res, body
}

// postJSON calls a method of the JSON API and decodes its response
func postJSON(t *testing.T, client *http.Client, u string, req any, res any) {
	t.Helper()
	body, err := json.Marshal(req)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), e2eHTTPTimeout)
	defer cancel()
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	require.NoError(t, err)
	r.Header.Set(header.ContentType, header.ApplicationJSON)
	resp, err := client.Do(r)
	require.NoError(t, err)
	defer resp.Body.Close()
	resBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(resBody))
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
