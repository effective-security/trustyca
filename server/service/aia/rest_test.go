package aia_test

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/gserver"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/config"
	"github.com/effective-security/trustyca/mocks/mockclient"
	"github.com/effective-security/trustyca/mocks/mocktrustycadb"
	"github.com/effective-security/trustyca/server/service/aia"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"golang.org/x/crypto/ocsp"
	"google.golang.org/grpc/codes"
)

// get serves a GET of the path
func (e *testEnv) get(t *testing.T, path string, headers ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	return e.serve(t, req)
}

// post serves a POST of the body to the path
func (e *testEnv) post(t *testing.T, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	return e.serve(t, httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body)))
}

// maxAgeOf returns the max-age of a public Cache-Control
func maxAgeOf(t *testing.T, w *httptest.ResponseRecorder) int {
	t.Helper()
	cc := w.Header().Get(header.CacheControl)
	require.True(t, strings.HasPrefix(cc, "public, no-transform, must-revalidate, max-age="), cc)
	n, err := strconv.Atoi(strings.TrimPrefix(cc, "public, no-transform, must-revalidate, max-age="))
	require.NoError(t, err, cc)
	return n
}

// requireNoStore asserts that the response is not cached
func requireNoStore(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	assert.Equal(t, "no-store", w.Header().Get(header.CacheControl))
	assert.Equal(t, "no-cache", w.Header().Get("Pragma"))
}

// TestRoutes registers the AIA routes on the router of the servers and
// checks that every path reaches its handler: the OCSP request of a GET is
// the URL-encoded base64 of the DER request, whose '/' and '+' are decoded
// before routing, so the body is a catch-all segment
func TestRoutes(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)

	// unsizedBody hides the length of a body from httptest.NewRequest, so
	// that the request declares no Content-Length
	type unsizedBody struct{ io.Reader }
	serveUnsized := func(method, path string, body []byte) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, unsizedBody{bytes.NewReader(body)})
		require.Equal(t, int64(-1), req.ContentLength)
		return e.serve(t, req)
	}

	// a request whose base64 has '+' and '/' in it: the sextets 62 and 63;
	// it is not an OCSP request, so the responder answers malformedRequest
	der := []byte{0xfb, 0xef, 0xbe, 0xff, 0xff, 0xff}
	encoded := base64.StdEncoding.EncodeToString(der)
	require.Contains(t, encoded, "/")
	require.Contains(t, encoded, "+")
	w := e.get(t, "/v1/ocsp/"+url.PathEscape(encoded))
	assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	assert.Equal(t, ocspContentType, w.Header().Get(header.ContentType))
	assert.Equal(t, ocsp.MalformedRequestErrorResponse, w.Body.Bytes())
	w = e.get(t, "/v1/ocsp/"+encoded)
	assert.Equal(t, http.StatusBadRequest, w.Code, "unescaped, as some clients send it")
	assert.Equal(t, ocsp.MalformedRequestErrorResponse, w.Body.Bytes())
	// the path is decoded once before routing, so a doubly-encoded body
	// reaches the handler with an escape it cannot decode
	w = e.get(t, "/v1/ocsp/%25zz")
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "unable to parse query")
	w = e.get(t, "/v1/ocsp/not-base64!")
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "unable to parse request")

	// the other OCSP routes; the body of a POST is bounded, whatever the
	// request declares
	w = e.post(t, pb.PathForOCSP, der)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, ocspContentType, w.Header().Get(header.ContentType))
	w = serveUnsized(http.MethodPost, pb.PathForOCSP, make([]byte, 8*1024))
	assert.Equal(t, http.StatusBadRequest, w.Code, "at the limit")
	assert.Equal(t, ocsp.MalformedRequestErrorResponse, w.Body.Bytes())
	w = serveUnsized(http.MethodPost, pb.PathForOCSP, make([]byte, 8*1024+1))
	assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
	assert.Contains(t, w.Body.String(), "request exceeds 8192 bytes")
	w = e.post(t, "/v1/ocspi/abc", der)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, ocsp.MalformedRequestErrorResponse, w.Body.Bytes())
	w = e.get(t, "/v1/ocspi/abc/"+url.PathEscape(encoded))
	assert.Equal(t, http.StatusBadRequest, w.Code, "the request in the path, by issuer")
	assert.Equal(t, ocspContentType, w.Header().Get(header.ContentType))
	w = e.get(t, "/v1/ocspi/abc/"+encoded)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	w = e.get(t, "/v1/ocspi/abc/not-base64!")
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "unable to parse request")

	// the AIA and CDP routes keep the paths of the issuer templates
	assert.Equal(t, "/v1/cert/:ikid", pb.PathForCert)
	assert.Equal(t, "/v1/crl/:ikid", pb.PathForCRL)
	w = e.get(t, "/v1/cert/abc")
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "issuer not found")
	w = e.get(t, "/v1/crl/abc")
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "CRL not found")
	w = e.get(t, "/v1/certi/abc")
	assert.Equal(t, http.StatusNotFound, w.Code)

	// the JSON API is the CIS's, on the wfe listener: the AIA does not
	// serve it
	w = e.post(t, pb.CIS_GetRoots_FullMethodName, []byte("{}"))
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "not found: "+pb.CIS_GetRoots_FullMethodName)
}

func TestIssuerHandler(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)

	w := e.get(t, "/v1/cert/"+e.issuer.Skid)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, certContentType, w.Header().Get(header.ContentType))
	assert.Equal(t, e.issuing.Cert.Raw, w.Body.Bytes())
	crt, err := x509.ParseCertificate(w.Body.Bytes())
	require.NoError(t, err)
	assert.Equal(t, e.issuing.Cert.Subject.String(), crt.Subject.String())
	// an issuer certificate never changes for its key identifier: a day of
	// caching, from the start of its validity
	maxAge := maxAgeOf(t, w)
	assert.InDelta(t, 24*60*60, maxAge, 5)
	assert.Equal(t, e.issuing.Cert.NotBefore.UTC().Format(http.TimeFormat), w.Header().Get("Last-Modified"))
	expires, err := http.ParseTime(w.Header().Get("Expires"))
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().Add(24*time.Hour), expires, 5*time.Second)
	etag := w.Header().Get("ETag")
	require.NotEmpty(t, etag)
	assert.True(t, strings.HasPrefix(etag, `"`) && strings.HasSuffix(etag, `"`), etag)
	w = e.get(t, "/v1/cert/"+e.issuer.Skid, "If-None-Match", etag)
	assert.Equal(t, http.StatusNotModified, w.Code)
	assert.Empty(t, w.Body.Bytes())
	assert.Equal(t, etag, w.Header().Get("ETag"))

	// a Pending issuer has no certificate, and an unknown one none
	w = e.get(t, "/v1/cert/"+pendingSKID)
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "issuer not found")
	w = e.get(t, "/v1/cert/nope")
	assert.Equal(t, http.StatusNotFound, w.Code)

	// a row whose PEM does not decode
	badPem := *e.issuer
	badPem.Skid = "bad-pem"
	badPem.Pem = "not a pem"
	e.store.mu.Lock()
	e.store.issuers[badPem.Skid] = &badPem
	e.store.mu.Unlock()
	w = e.get(t, "/v1/cert/bad-pem")
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "unable to decode certificate")

	e.store.setFail(errors.New("db down"))
	w = e.get(t, "/v1/cert/"+e.issuer.Skid)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "unable to find issuer")
}

func TestCRLHandler(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)

	w := e.get(t, "/v1/crl/"+e.issuer.Skid)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, crlContentType, w.Header().Get(header.ContentType))
	crl, err := x509.ParseRevocationList(w.Body.Bytes())
	require.NoError(t, err)
	require.NoError(t, crl.CheckSignatureFrom(e.issuing.Cert))
	assert.EqualValues(t, testCrlNumber, crl.Number.Int64())
	require.Len(t, crl.RevokedCertificateEntries, 1)
	assert.Equal(t, 0, e.revCrt.SerialNumber.Cmp(crl.RevokedCertificateEntries[0].SerialNumber))
	// cached until the next update of the CRL
	maxAge := maxAgeOf(t, w)
	assert.InDelta(t, time.Until(e.crl.NextUpdate.UTC()).Seconds(), maxAge, 5)
	assert.Equal(t, e.crl.ThisUpdate.UTC().Format(http.TimeFormat), w.Header().Get("Last-Modified"))
	assert.Equal(t, e.crl.NextUpdate.UTC().Format(http.TimeFormat), w.Header().Get("Expires"))
	etag := w.Header().Get("ETag")
	require.NotEmpty(t, etag)
	w = e.get(t, "/v1/crl/"+e.issuer.Skid, "If-None-Match", etag)
	assert.Equal(t, http.StatusNotModified, w.Code)
	w = e.get(t, "/v1/crl/"+e.issuer.Skid, "If-None-Match", `"other"`)
	assert.Equal(t, http.StatusOK, w.Code)

	// a CRL past its next update is served, since it is the current one,
	// but not cached
	e.store.mu.Lock()
	stale := *e.crl
	stale.Ikid = "stale"
	stale.NextUpdate = stale.ThisUpdate
	e.store.crls["stale"] = &stale
	bad := *e.crl
	bad.Ikid = "bad-pem"
	bad.Pem = "not a pem"
	e.store.crls["bad-pem"] = &bad
	e.store.mu.Unlock()
	w = e.get(t, "/v1/crl/stale")
	assert.Equal(t, http.StatusOK, w.Code)
	requireNoStore(t, w)
	w = e.get(t, "/v1/crl/bad-pem")
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "unable to decode CRL")

	w = e.get(t, "/v1/crl/nope")
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "CRL not found")
	e.store.setFail(errors.New("db down"))
	w = e.get(t, "/v1/crl/"+e.issuer.Skid)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "unable to find CRL")
}

func TestOCSPHandlers(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)

	// good, by GET with the request in the path, under both routes
	goodReq := e.ocspRequest(t, e.leafCrt, crypto.SHA256)
	path := "/v1/ocsp/" + url.PathEscape(base64.StdEncoding.EncodeToString(goodReq))
	w := e.get(t, path)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, ocspContentType, w.Header().Get(header.ContentType))
	res, err := ocsp.ParseResponseForCert(w.Body.Bytes(), e.leafCrt, e.issuing.Cert)
	require.NoError(t, err)
	assert.Equal(t, ocsp.Good, res.Status)
	assert.Equal(t, 1, e.ca.count())
	maxAge := maxAgeOf(t, w)
	assert.InDelta(t, ocspValidity.Seconds(), maxAge, 5)
	assert.Equal(t, res.ThisUpdate.UTC().Format(http.TimeFormat), w.Header().Get("Last-Modified"))
	assert.Equal(t, res.NextUpdate.UTC().Format(http.TimeFormat), w.Header().Get("Expires"))
	etag := w.Header().Get("ETag")
	require.NotEmpty(t, etag)
	first := w.Body.Bytes()

	// the same request is answered from the cache, by any route
	w = e.get(t, path)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, first, w.Body.Bytes())
	assert.Equal(t, 1, e.ca.count(), "cached")
	assert.Equal(t, etag, w.Header().Get("ETag"))
	assert.LessOrEqual(t, maxAgeOf(t, w), maxAge)
	w = e.get(t, path, "If-None-Match", etag)
	assert.Equal(t, http.StatusNotModified, w.Code)
	w = e.post(t, pb.PathForOCSP, goodReq)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, first, w.Body.Bytes())
	w = e.post(t, "/v1/ocspi/"+e.issuer.Skid, goodReq)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, first, w.Body.Bytes())
	w = e.get(t, "/v1/ocspi/"+e.issuer.Skid+"/"+url.PathEscape(base64.StdEncoding.EncodeToString(goodReq)))
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, first, w.Body.Bytes())
	assert.Equal(t, 1, e.ca.count())

	// another hash is another request; a nonce too
	sha1Req := e.ocspRequest(t, e.leafCrt, crypto.SHA1)
	w = e.post(t, pb.PathForOCSP, sha1Req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, 2, e.ca.count())
	res, err = ocsp.ParseResponseForCert(w.Body.Bytes(), e.leafCrt, e.issuing.Cert)
	require.NoError(t, err)
	assert.Equal(t, ocsp.Good, res.Status)

	// revoked, with the reason and time of the revocation
	revReq := e.ocspRequest(t, e.revCrt, crypto.SHA256)
	w = e.post(t, pb.PathForOCSP, revReq)
	require.Equal(t, http.StatusOK, w.Code)
	res, err = ocsp.ParseResponseForCert(w.Body.Bytes(), e.revCrt, e.issuing.Cert)
	require.NoError(t, err)
	assert.Equal(t, ocsp.Revoked, res.Status)
	assert.Equal(t, ocsp.KeyCompromise, res.RevocationReason)
	assert.Equal(t, e.revRow.RevokedAt.UTC(), res.RevokedAt.UTC())

	// unknown serial
	unknown := e.issuing.Issue(t, "unknown.example.com", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	w = e.post(t, pb.PathForOCSP, e.ocspRequest(t, unknown, crypto.SHA256))
	require.Equal(t, http.StatusOK, w.Code)
	res, err = ocsp.ParseResponseForCert(w.Body.Bytes(), unknown, e.issuing.Cert)
	require.NoError(t, err)
	assert.Equal(t, ocsp.Unknown, res.Status)

	// an issuer the CA does not serve is unauthorized; not cached
	otherLeaf := e.other.Issue(t, "other.example.com", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	otherReq, err := ocsp.CreateRequest(otherLeaf, e.other.Cert, nil)
	require.NoError(t, err)
	calls := e.ca.count()
	w = e.post(t, pb.PathForOCSP, otherReq)
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Equal(t, ocspContentType, w.Header().Get(header.ContentType))
	assert.Equal(t, ocsp.UnauthorizedErrorResponse, w.Body.Bytes())
	requireNoStore(t, w)
	w = e.post(t, pb.PathForOCSP, otherReq)
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Equal(t, calls+2, e.ca.count(), "errors are not cached")

	// the failures of the CA, for requests that are not cached
	freshReq := func() []byte {
		return e.ocspRequest(t, e.issuing.Issue(t, "fresh.example.com", time.Now().Add(-time.Hour), time.Now().Add(time.Hour)), crypto.SHA256)
	}
	for _, tc := range []struct {
		code   codes.Code
		status int
		body   []byte
	}{
		{codes.InvalidArgument, http.StatusBadRequest, ocsp.MalformedRequestErrorResponse},
		{codes.NotFound, http.StatusNotFound, ocsp.UnauthorizedErrorResponse},
		{codes.Unavailable, http.StatusServiceUnavailable, ocsp.TryLaterErrorResponse},
		{codes.DeadlineExceeded, http.StatusServiceUnavailable, ocsp.TryLaterErrorResponse},
		{codes.Internal, http.StatusInternalServerError, ocsp.InternalErrorErrorResponse},
		{codes.PermissionDenied, http.StatusInternalServerError, ocsp.InternalErrorErrorResponse},
	} {
		e.ca.setFail(httperror.NewGrpc(tc.code, "failed"))
		w = e.post(t, pb.PathForOCSP, freshReq())
		assert.Equal(t, tc.status, w.Code, tc.code.String())
		assert.Equal(t, tc.body, w.Body.Bytes(), tc.code.String())
		requireNoStore(t, w)
	}
	e.ca.setFail(errors.New("plain failure"))
	w = e.post(t, pb.PathForOCSP, freshReq())
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Equal(t, ocsp.InternalErrorErrorResponse, w.Body.Bytes())
	e.ca.setFail(nil)
	// the cached good response is still served while the CA fails
	e.ca.setFail(httperror.NewGrpc(codes.Unavailable, "down"))
	w = e.post(t, pb.PathForOCSP, goodReq)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, first, w.Body.Bytes())
	e.ca.setFail(nil)

	// a response that is already stale is served but not cached
	e.ca.setValidity(0)
	calls = e.ca.count()
	expiredReq := e.ocspRequest(t, e.expCrt, crypto.SHA256)
	w = e.post(t, pb.PathForOCSP, expiredReq)
	assert.Equal(t, http.StatusOK, w.Code)
	requireNoStore(t, w)
	w = e.post(t, pb.PathForOCSP, expiredReq)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, calls+2, e.ca.count())
	e.ca.setValidity(ocspValidity)

	// bytes that are not a response are passed through and not cached
	e.ca.setGarbage(true)
	calls = e.ca.count()
	w = e.post(t, pb.PathForOCSP, expiredReq)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "not an OCSP response", w.Body.String())
	requireNoStore(t, w)
	w = e.post(t, pb.PathForOCSP, expiredReq)
	assert.Equal(t, calls+2, e.ca.count())
	e.ca.setGarbage(false)
}

// TestOCSPHandler_CAClient covers the client of the backend the service
// creates on the first request when it is given no CA: a factory that
// fails answers tryLater, and the next request tries again
func TestOCSPHandler_CAClient(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	cadb := mocktrustycadb.NewMockCaReadonlyDb(ctrl)
	goodReq := e.ocspRequest(t, e.leafCrt, crypto.SHA256)

	// no CA and no factory
	svc, err := aia.New(&config.Configuration{}, cadb, nil, nil)
	require.NoError(t, err)
	w := httptest.NewRecorder()
	svc.OCSPHandler()(w, httptest.NewRequest(http.MethodPost, pb.PathForOCSP, bytes.NewReader(goodReq)), nil)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Equal(t, ocsp.TryLaterErrorResponse, w.Body.Bytes())
	requireNoStore(t, w)

	// a factory that fails, then one that connects; the client is kept and
	// closed with the service
	factory := mockclient.NewMockFactory(ctrl)
	closer := &countingCloser{}
	gomock.InOrder(
		factory.EXPECT().CAClient(config.BackendServerName).Return(nil, nil, errors.New("backend down")),
		factory.EXPECT().CAClient(config.BackendServerName).Return(e.ca, closer, nil),
	)
	svc, err = aia.New(&config.Configuration{}, cadb, nil, factory)
	require.NoError(t, err)
	w = httptest.NewRecorder()
	svc.OCSPHandler()(w, httptest.NewRequest(http.MethodPost, pb.PathForOCSP, bytes.NewReader(goodReq)), nil)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Equal(t, ocsp.TryLaterErrorResponse, w.Body.Bytes())
	for range 2 {
		w = httptest.NewRecorder()
		svc.OCSPHandler()(w, httptest.NewRequest(http.MethodPost, pb.PathForOCSP, bytes.NewReader(goodReq)), nil)
		assert.Equal(t, http.StatusOK, w.Code)
	}
	assert.Equal(t, 1, e.ca.count())
	svc.Close()
	assert.Equal(t, 1, closer.closed)

	// the AIA certificate must load when it is configured
	factory = mockclient.NewMockFactory(ctrl)
	svc, err = aia.New(&config.Configuration{AIA: config.AIA{ClientTLS: gserver.TLSInfo{
		CertFile:      "/nope/cis.pem",
		KeyFile:       "/nope/cis.key",
		TrustedCAFile: "/nope/root.pem",
	}}}, cadb, nil, factory)
	require.NoError(t, err)
	w = httptest.NewRecorder()
	svc.OCSPHandler()(w, httptest.NewRequest(http.MethodPost, pb.PathForOCSP, bytes.NewReader(goodReq)), nil)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Equal(t, ocsp.TryLaterErrorResponse, w.Body.Bytes())
}

// countingCloser counts its closes
type countingCloser struct {
	closed int
}

func (c *countingCloser) Close() error {
	c.closed++
	return nil
}
