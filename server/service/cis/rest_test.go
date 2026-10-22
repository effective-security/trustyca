package cis_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// postJSON serves a JSON request of the API and decodes the response
func (e *testEnv) postJSON(t *testing.T, path string, req any, res any) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(req)
	require.NoError(t, err)
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	r.Header.Set(header.ContentType, header.ApplicationJSON)
	r.Header.Set(header.Accept, header.ApplicationJSON)
	w := e.serve(t, r)
	if res != nil && w.Code == http.StatusOK {
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), res), w.Body.String())
	}
	return w
}

// TestRoutes registers the CIS routes on the router of the servers and
// checks that every method of the JSON API reaches the service through
// httppb, and that the binary AIA routes are not the CIS's
func TestRoutes(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)

	assert.Equal(t, "/pb.CIS/:action", pb.PathForCIS)
	var info pb.IssuerInfo
	w := e.postJSON(t, pb.CIS_GetIssuer_FullMethodName, &pb.GetIssuerInfoRequest{IKID: e.issuer.Skid}, &info)
	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Contains(t, w.Header().Get(header.ContentType), header.ApplicationJSON)
	assert.Equal(t, testIssuerLabel, info.Label)
	assert.Equal(t, e.issuer.Pem, info.Certificate)
	assert.Equal(t, "http://aia.test/v1/cert/"+e.issuer.Skid, info.AiaURL)
	w = e.postJSON(t, pb.CIS_GetIssuer_FullMethodName, &pb.GetIssuerInfoRequest{IKID: "nope"}, nil)
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "issuer not found")
	w = e.postJSON(t, "/pb.CIS/Nope", &pb.GetIssuerInfoRequest{}, nil)
	assert.Equal(t, http.StatusNotFound, w.Code)
	var crl pb.CrlResponse
	w = e.postJSON(t, pb.CIS_GetCRL_FullMethodName, &pb.GetCrlRequest{IKID: e.issuer.Skid}, &crl)
	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, "3", crl.Crl.Number)
	assert.Empty(t, crl.Crl.OrgID)
	var cert pb.CertificateResponse
	w = e.postJSON(t, pb.CIS_GetCertificate_FullMethodName, &pb.GetCertificateInfoRequest{Sha256: e.leaf.Sha256}, &cert)
	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, e.leaf.Pem, cert.Certificate.Pem)
	assert.Empty(t, cert.Certificate.OrgID)
	var status pb.CertificateStatusResponse
	w = e.postJSON(t, pb.CIS_GetCertificateStatus_FullMethodName, &pb.GetCertificateInfoRequest{ID: e.revoked.ID.String()}, &status)
	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, pb.CertificateStatus_Revoked, status.Status)
	assert.Equal(t, pb.ReasonCode_KeyCompromise, status.Reason)
	var roots pb.RootsResponse
	w = e.postJSON(t, pb.CIS_GetRoots_FullMethodName, &pb.ListRootsRequest{}, &roots)
	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Len(t, roots.Roots, 1)

	// the binary routes of the issued certificates are the AIA's, on its
	// own listener: the CIS does not serve them
	for _, path := range []string{"/v1/cert/" + e.issuer.Skid, "/v1/crl/" + e.issuer.Skid, "/v1/ocsp/MAo="} {
		w = e.serve(t, httptest.NewRequest(http.MethodGet, path, nil))
		assert.Equal(t, http.StatusNotFound, w.Code, path)
		assert.Contains(t, w.Body.String(), "not found: "+path)
	}
	w = e.serve(t, httptest.NewRequest(http.MethodPost, pb.PathForOCSP, bytes.NewReader([]byte("0"))))
	assert.Equal(t, http.StatusNotFound, w.Code)
}
