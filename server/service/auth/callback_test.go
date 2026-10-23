package auth_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/server/service/auth"
	"github.com/effective-security/xpki/jwt/oauth2client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"google.golang.org/grpc/codes"
)

func TestGetUserInfo(t *testing.T) {
	// Can't run in parallel because of the server.URL
	//t.Parallel()

	service := testServer.Service(auth.ServiceName).(*auth.Service)
	require.NotNil(t, service)

	// Mock the token
	token := &oauth2.Token{AccessToken: "mockAccessToken"}

	var (
		response string
		status   = http.StatusOK
	)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = io.WriteString(w, response)
	})

	server := httptest.NewServer(h)
	defer server.Close()

	clientConfig := &oauth2client.ClientConfig{ProviderID: "someProvider", UserinfoURL: server.URL + "/userinfo"}

	oldURL := service.BaseURL
	service.BaseURL, _ = url.Parse(server.URL)
	defer func() { service.BaseURL = oldURL }()

	t.Run("empty name2", func(t *testing.T) {
		response = `{"email": "test.user@example.com"}`
		// Call getUser
		userInfo, _, err := service.GetUserInfo(context.Background(), pb.IDP_Github, clientConfig, nil, token)

		// Assertions
		require.NoError(t, err)
		assert.Equal(t, "Test User", userInfo.Name)
		assert.Equal(t, "test.user@example.com", userInfo.Email)
	})

	t.Run("empty name1", func(t *testing.T) {
		response = `{"email": "denis@example.com"}`
		// Call getUser
		userInfo, _, err := service.GetUserInfo(context.Background(), pb.IDP_Github, clientConfig, nil, token)

		// Assertions
		require.NoError(t, err)
		assert.Equal(t, "Denis", userInfo.Name)
		assert.Equal(t, "denis@example.com", userInfo.Email)
	})

	t.Run("non empty name", func(t *testing.T) {
		response = `{"email": "test.user@example.com", "name": "Test User"}`
		// Call getUser
		userInfo, _, err := service.GetUserInfo(context.Background(), pb.IDP_Github, clientConfig, nil, token)

		// Assertions
		require.NoError(t, err)
		assert.Equal(t, "Test User", userInfo.Name)
		assert.Equal(t, "test.user@example.com", userInfo.Email)
	})

	t.Run("no email", func(t *testing.T) {
		response = `{"name": "Test User"}`
		_, _, err := service.GetUserInfo(context.Background(), pb.IDP_Google, clientConfig, nil, token)
		var he *httperror.Error
		require.True(t, errors.As(err, &he), "%T", err)
		assert.Equal(t, codes.PermissionDenied, he.RPCStatus)
		assert.Equal(t, "email is required", he.Message)
	})

	t.Run("idp failure", func(t *testing.T) {
		status = http.StatusUnauthorized
		defer func() { status = http.StatusOK }()
		response = `{"message": "Bad credentials"}`
		_, _, err := service.GetUserInfo(context.Background(), pb.IDP_Google, clientConfig, nil, token)
		var he *httperror.Error
		require.True(t, errors.As(err, &he), "%T", err)
		assert.Equal(t, codes.Unavailable, he.RPCStatus)
		// the answer of the IdP is in the cause only
		assert.Equal(t, "unable to get user info", he.Message)
		require.Error(t, he.Cause())
		assert.Contains(t, he.Cause().Error(), "401 Unauthorized")
		assert.Contains(t, he.Cause().Error(), "Bad credentials")
	})
}

// TestCallbackHandler_ErrorRedirect checks that a login that fails after
// its state is decoded lands on the redirect URI of the client, in the
// response mode of the state, with the OAuth error code and description
func TestCallbackHandler_ErrorRedirect(t *testing.T) {
	t.Parallel()
	service := testServer.Service(auth.ServiceName).(*auth.Service)
	h := service.CallbackHandler()

	const redirect = "https://localhost:38989/landing"
	now := time.Now()

	tcs := []struct {
		name     string
		mode     string
		provider pb.IDP_Enum
		issuedAt time.Time
		params   url.Values
		exp      url.Values
	}{
		{
			name:     "idp_error",
			mode:     "query",
			provider: pb.IDP_Github,
			issuedAt: now,
			params: url.Values{
				pb.OAuthParamError:            {pb.OAuthErrorAccessDenied},
				pb.OAuthParamErrorDescription: {"the user declined"},
			},
			exp: url.Values{
				pb.OAuthParamError:            {pb.OAuthErrorAccessDenied},
				pb.OAuthParamErrorDescription: {"OAuth provider error: the user declined"},
			},
		},
		{
			// a code outside of RFC 6749 section 4.1.2.1 is mapped by its status
			name:     "idp_error_other_code",
			mode:     "query",
			provider: pb.IDP_Github,
			issuedAt: now,
			params: url.Values{
				pb.OAuthParamError: {"invalid_grant"},
			},
			exp: url.Values{
				pb.OAuthParamError:            {pb.OAuthErrorInvalidRequest},
				pb.OAuthParamErrorDescription: {"OAuth provider error: invalid_grant"},
			},
		},
		{
			name:     "expired_state",
			mode:     "fragment",
			provider: pb.IDP_Github,
			issuedAt: now.Add(-10 * time.Minute),
			params:   url.Values{"code": {"abc"}},
			exp: url.Values{
				pb.OAuthParamError:            {pb.OAuthErrorInvalidRequest},
				pb.OAuthParamErrorDescription: {"invalid state"},
			},
		},
		{
			name:     "missing_code",
			mode:     "query",
			provider: pb.IDP_Github,
			issuedAt: now,
			exp: url.Values{
				pb.OAuthParamError:            {pb.OAuthErrorInvalidRequest},
				pb.OAuthParamErrorDescription: {"missing code parameter"},
			},
		},
		{
			// no provider is registered for the state; the other tests
			// register Gitlab on the shared service
			name:     "unsupported_provider",
			mode:     "form_post",
			provider: pb.IDP_Undefined,
			issuedAt: now,
			params:   url.Values{"code": {"abc"}},
			exp: url.Values{
				pb.OAuthParamError:            {pb.OAuthErrorInvalidRequest},
				pb.OAuthParamErrorDescription: {"unsupported provider: Undefined"},
			},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			st, err := service.Protect(t.Context(), &auth.State{
				ResponseType: pb.OAuthResponseTypeCode,
				ResponseMode: tc.mode,
				RedirectURL:  redirect,
				Provider:     tc.provider,
				IssuedAt:     tc.issuedAt.Unix(),
			})
			require.NoError(t, err)
			params := url.Values{"state": {st}}
			for k, v := range tc.params {
				params[k] = v
			}

			w := httptest.NewRecorder()
			r, err := http.NewRequest(http.MethodGet, pb.PathForAuthCallback+"?"+params.Encode(), nil)
			require.NoError(t, err)
			h(w, r, nil)

			if tc.mode == "form_post" {
				require.Equal(t, http.StatusOK, w.Code)
				body := w.Body.String()
				assert.Contains(t, body, `action="`+redirect+`"`)
				for k, v := range tc.exp {
					assert.Contains(t, body, `name="`+k+`" value="`+v[0]+`"`)
				}
				return
			}
			require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
			loc, err := url.Parse(w.Header().Get(header.Location))
			require.NoError(t, err)
			assert.Equal(t, redirect, loc.Scheme+"://"+loc.Host+loc.Path)
			res := loc.Query()
			if tc.mode == "fragment" {
				assert.Empty(t, loc.RawQuery)
				res, err = url.ParseQuery(loc.Fragment)
				require.NoError(t, err)
			}
			assert.Equal(t, tc.exp, res)
		})
	}

	t.Run("idp_error_without_state", func(t *testing.T) {
		t.Parallel()
		// the redirect URI of the client is unknown: the error stays on the
		// API host
		w := httptest.NewRecorder()
		r, err := http.NewRequest(http.MethodGet, pb.PathForAuthCallback+"?error=access_denied&state=bad", nil)
		require.NoError(t, err)
		h(w, r, nil)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Empty(t, w.Header().Get(header.Location))
		assert.True(t, strings.HasPrefix(w.Header().Get(header.ContentType), "application/json"), w.Header().Get(header.ContentType))
		assert.Equal(t, `{"code":"access_denied","message":"OAuth provider error: access_denied"}`, w.Body.String())
	})
}
