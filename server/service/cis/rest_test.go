package cis_test

import (
	"bytes"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/effective-security/porto/restserver"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/server/service/cis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ocspContentType is the media type of an OCSP response
const ocspContentType = "application/ocsp-response"

// TestRoutes registers the CIS routes on the router of the servers and
// checks that every path reaches its handler: the OCSP request of a GET is
// the URL-encoded base64 of the DER request, whose '/' and '+' are decoded
// before routing, so the body is a catch-all segment
func TestRoutes(t *testing.T) {
	t.Parallel()
	r := restserver.NewRouter(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found: "+r.URL.Path, http.StatusNotFound)
	})
	(&cis.Service{}).RegisterRoute(r)
	h := r.Handler()

	serve := func(method, path string, body string) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(method, path, strings.NewReader(body)))
		return w
	}
	// unsizedBody hides the length of a body from httptest.NewRequest, so
	// that the request declares no Content-Length
	type unsizedBody struct{ io.Reader }
	serveUnsized := func(method, path string, body []byte) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, unsizedBody{bytes.NewReader(body)})
		require.Equal(t, int64(-1), req.ContentLength)
		h.ServeHTTP(w, req)
		return w
	}

	// a request whose base64 has '+' and '/' in it: the sextets 62 and 63
	der := []byte{0xfb, 0xef, 0xbe, 0xff, 0xff, 0xff}
	encoded := base64.StdEncoding.EncodeToString(der)
	require.Contains(t, encoded, "/")
	require.Contains(t, encoded, "+")
	w := serve(http.MethodGet, "/v1/ocsp/"+url.PathEscape(encoded), "")
	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, ocspContentType, w.Header().Get(header.ContentType))
	w = serve(http.MethodGet, "/v1/ocsp/"+encoded, "")
	assert.Equal(t, http.StatusOK, w.Code, "unescaped, as some clients send it")
	// the path is decoded once before routing, so a doubly-encoded body
	// reaches the handler with an escape it cannot decode
	w = serve(http.MethodGet, "/v1/ocsp/%25zz", "")
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "unable to parse query")
	w = serve(http.MethodGet, "/v1/ocsp/not-base64!", "")
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "unable to parse request")

	// the other OCSP routes; the body of a POST is bounded, whatever the
	// request declares
	w = serve(http.MethodPost, pb.PathForOCSP, string(der))
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, ocspContentType, w.Header().Get(header.ContentType))
	w = serveUnsized(http.MethodPost, pb.PathForOCSP, make([]byte, 8*1024))
	assert.Equal(t, http.StatusOK, w.Code, "at the limit")
	w = serveUnsized(http.MethodPost, pb.PathForOCSP, make([]byte, 8*1024+1))
	assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
	assert.Contains(t, w.Body.String(), "request exceeds 8192 bytes")
	w = serve(http.MethodPost, "/v1/ocspi/abc", string(der))
	assert.Equal(t, http.StatusOK, w.Code)
	w = serve(http.MethodGet, "/v1/ocspi/abc/"+url.PathEscape(encoded), "")
	assert.Equal(t, http.StatusOK, w.Code, "the request in the path, by issuer")
	assert.Equal(t, ocspContentType, w.Header().Get(header.ContentType))
	w = serve(http.MethodGet, "/v1/ocspi/abc/"+encoded, "")
	assert.Equal(t, http.StatusOK, w.Code)
	w = serve(http.MethodGet, "/v1/ocspi/abc/not-base64!", "")
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// the AIA and CDP routes keep the paths of the issuer templates
	assert.Equal(t, "/v1/cert/:ikid", pb.PathForCert)
	assert.Equal(t, "/v1/crl/:ikid", pb.PathForCRL)
	w = serve(http.MethodGet, "/v1/cert/abc", "")
	assert.Equal(t, http.StatusOK, w.Code)
	w = serve(http.MethodGet, "/v1/crl/abc", "")
	assert.Equal(t, http.StatusOK, w.Code)
	w = serve(http.MethodGet, "/v1/certi/abc", "")
	assert.Equal(t, http.StatusNotFound, w.Code)
}
