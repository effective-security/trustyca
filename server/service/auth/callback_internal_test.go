package auth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func Test_oauthErrorCode(t *testing.T) {
	t.Parallel()
	tcs := []struct {
		name string
		err  *httperror.Error
		exp  string
	}{
		{"oauth_code", httperror.FromOAuth(pb.OAuthErrorInvalidScope, "x"), pb.OAuthErrorInvalidScope},
		{"invalid_request", httperror.InvalidRequest("x"), pb.OAuthErrorInvalidRequest},
		{"bad_request", httperror.NewGrpcFromCtx(t.Context(), codes.InvalidArgument, "x"), pb.OAuthErrorInvalidRequest},
		{"forbidden", httperror.Forbidden("x"), pb.OAuthErrorAccessDenied},
		{"permission_denied", httperror.NewGrpcFromCtx(t.Context(), codes.PermissionDenied, "x"), pb.OAuthErrorAccessDenied},
		{"unauthorized", httperror.Unauthorized("x"), pb.OAuthErrorAccessDenied},
		{"unexpected", httperror.Unexpected("x"), pb.OAuthErrorServerError},
		{"unavailable", httperror.NewGrpcFromCtx(t.Context(), codes.Unavailable, "x"), pb.OAuthErrorTemporarilyUnavailable},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.exp, oauthErrorCode(tc.err))
		})
	}
}

func Test_writeOauthResponse(t *testing.T) {
	t.Parallel()
	vals := url.Values{
		pb.OAuthParamError:            {pb.OAuthErrorAccessDenied},
		pb.OAuthParamErrorDescription: {"no access"},
	}
	tcs := []struct {
		name     string
		redirect string
		mode     string
		exp      string
	}{
		{"query", "https://client/cb", "", "https://client/cb?error=access_denied&error_description=no+access"},
		// the parameters are merged into the query of the redirect URI
		{"query_of_client", "https://client/cb?tenant=1", "query", "https://client/cb?error=access_denied&error_description=no+access&tenant=1"},
		{"fragment", "https://client/cb?tenant=1", "fragment", "https://client/cb?tenant=1#error=access_denied&error_description=no+access"},
		// the fragment of the redirect URI is replaced
		{"fragment_of_client", "https://client/cb#old", "fragment", "https://client/cb#error=access_denied&error_description=no+access"},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, pb.PathForAuthCallback, nil)
			writeOauthResponse(w, r, &State{RedirectURL: tc.redirect, ResponseMode: tc.mode}, vals)
			require.Equal(t, http.StatusSeeOther, w.Code)
			assert.Equal(t, tc.exp, w.Header().Get(header.Location))
		})
	}

	// form_post posts the parameters to the redirect URI as it is
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, pb.PathForAuthCallback, nil)
	writeOauthResponse(w, r, &State{RedirectURL: "https://client/cb?tenant=1", ResponseMode: "form_post"}, vals)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `action="https://client/cb?tenant=1"`)
	assert.Contains(t, w.Body.String(), `name="error" value="access_denied"`)
}

func Test_writeOauthError(t *testing.T) {
	t.Parallel()
	const redirect = "https://localhost:38989/landing"
	st := &State{
		RedirectURL:  redirect,
		ResponseMode: "query",
		Provider:     pb.IDP_Github,
	}

	location := func(t *testing.T, err error) url.Values {
		t.Helper()
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, pb.PathForAuthCallback, nil)
		writeOauthError(w, r, st, err)
		require.Equal(t, http.StatusSeeOther, w.Code)
		loc, perr := url.Parse(w.Header().Get(header.Location))
		require.NoError(t, perr)
		assert.Equal(t, redirect, loc.Scheme+"://"+loc.Host+loc.Path)
		return loc.Query()
	}

	// a refusal keeps its message
	assert.Equal(t, url.Values{
		pb.OAuthParamError:            {pb.OAuthErrorAccessDenied},
		pb.OAuthParamErrorDescription: {"email mismatch: provider: Github"},
	}, location(t, httperror.Forbidden("email mismatch: provider: %s", st.Provider)))

	// a server-side failure is described by its status only, never by its
	// message or cause
	assert.Equal(t, url.Values{
		pb.OAuthParamError:            {pb.OAuthErrorServerError},
		pb.OAuthParamErrorDescription: {http.StatusText(http.StatusInternalServerError)},
	}, location(t, httperror.Unexpected("failed to login").WithCause(errors.New("pq: connection refused"))))
	assert.Equal(t, url.Values{
		pb.OAuthParamError:            {pb.OAuthErrorTemporarilyUnavailable},
		pb.OAuthParamErrorDescription: {http.StatusText(http.StatusServiceUnavailable)},
	}, location(t, httperror.NewGrpcFromCtx(t.Context(), codes.Unavailable, "unable to get user info")))

	// an error of another kind is a server-side failure
	assert.Equal(t, url.Values{
		pb.OAuthParamError:            {pb.OAuthErrorServerError},
		pb.OAuthParamErrorDescription: {http.StatusText(http.StatusInternalServerError)},
	}, location(t, errors.New("db down")))
}
