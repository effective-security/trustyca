package auth_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/gserver"
	"github.com/effective-security/porto/pkg/retriable"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/identity"
	"github.com/effective-security/servefiles"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/api/pb/proxypb"
	"github.com/effective-security/trustyca/internal/config"
	"github.com/effective-security/trustyca/server/appcontainer"
	"github.com/effective-security/trustyca/server/service/auth"
	"github.com/effective-security/trustyca/tests/testutils"
	"github.com/effective-security/x/urlutil"
	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/jwt"
	"github.com/effective-security/xpki/jwt/dpop"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/emptypb"
)

var (
	testServer gserver.GServer
	dpopSigner dpop.Signer
	authClient pb.AuthServer
	httpAddr   string
)

var jsonContentHeaders = map[string]string{
	header.Accept:      header.ApplicationJSON,
	header.ContentType: header.ApplicationJSON,
}

var textContentHeaders = map[string]string{
	header.Accept:      header.TextPlain,
	header.ContentType: header.ApplicationJSON,
}

// serviceFactories provides map of gserver.ServiceFactory
var serviceFactories = map[string]gserver.ServiceFactory{
	auth.ServiceName: auth.Factory,
}

func TestMain(m *testing.M) {
	var err error

	httpAddr = testutils.CreateURL("http", "")

	cfg := &gserver.Config{
		ListenURLs: []string{httpAddr},
		Services:   []string{auth.ServiceName},
	}

	closer := appcontainer.NewCloser(4)
	f := appcontainer.NewContainerFactory(closer).
		WithConfigurationProvider(func() (*config.Configuration, error) {
			return testutils.LoadConfig("UNIT_TEST")
		})
	container, err := f.CreateContainerWithDependencies()
	if err != nil {
		panic(errors.WithStack(err))
	}

	testServer, err = gserver.Start("AuthTest", cfg, container, serviceFactories)
	if err != nil || testServer == nil {
		panic(errors.WithStack(err))
	}

	serviceServer := testServer.Service(auth.ServiceName).(pb.AuthServer)
	authClient = proxypb.NewAuthClientFromProxy(proxypb.AuthServerToClient(serviceServer))

	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	dpopSigner, err = dpop.NewSigner(ecKey)
	if err != nil || dpopSigner == nil {
		panic(errors.WithStack(err))
	}

	os.Setenv("TRUSTYCA_GITHUB_CLIENT_ID", "testclientid")
	os.Setenv("TRUSTYCA_GITHUB_CLIENT_SECRET", "testclientsecret")
	os.Setenv("TRUSTYCA_GOOGLE_CLIENT_ID", "testclientid")
	os.Setenv("TRUSTYCA_GOOGLE_CLIENT_SECRET", "testclientsecret")

	// Run the tests
	rc := m.Run()

	// cleanup
	testServer.Close()
	closer.Close()

	time.Sleep(time.Second)

	os.Exit(rc)
}

func TestIsReady(t *testing.T) {
	t.Parallel()
	service := testServer.Service(auth.ServiceName).(*auth.Service)
	require.NotNil(t, service)
	assert.True(t, service.IsReady())

	ctx := context.Background()
	_, err := service.AuthProvider(ctx, pb.IDP_Github)
	require.NoError(t, err)
}

func TestClose(t *testing.T) {
	t.Parallel()
	service := new(auth.Service)
	assert.NotPanics(t, service.Close)
	assert.NotPanics(t, service.Close)
}

func TestFactory(t *testing.T) {
	t.Parallel()
	assert.Panics(t, func() {
		auth.Factory(nil)
	})
}

func Test_AuthProvidersHandler(t *testing.T) {
	t.Parallel()
	service := testServer.Service(auth.ServiceName).(*auth.Service)
	require.NotNil(t, service)

	h := service.AuthProvidersHandler()
	w := httptest.NewRecorder()
	r, err := http.NewRequest(http.MethodGet, pb.PathForAuthProviders, nil)
	require.NoError(t, err)

	h(w, r, nil)
	assert.Equal(t, http.StatusOK, w.Code)

	var res pb.AuthProvidersResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &res))
	assert.NotEmpty(t, res.AuthURL)
	assert.NotEmpty(t, res.Providers)
}

func Test_AuthProvidersHandlerPost(t *testing.T) {
	t.Parallel()
	service := testServer.Service(auth.ServiceName).(*auth.Service)
	require.NotNil(t, service)

	h := service.AuthProvidersHandler()
	req := &pb.AuthProvidersRequest{
		Email: "",
	}

	w, r, err := testutils.CreateRequest(http.MethodPost, pb.PathForAuthProviders, req, nil)
	require.NoError(t, err)

	h(w, r, nil)
	assert.Equal(t, http.StatusOK, w.Code)

	var res pb.AuthProvidersResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &res))
	assert.NotEmpty(t, res.AuthURL)
	assert.NotEmpty(t, res.Providers)
}

func Test_AuthDoneHandler(t *testing.T) {
	t.Parallel()
	service := testServer.Service(auth.ServiceName).(*auth.Service)
	require.NotNil(t, service)

	h := service.AuthDoneHandler()

	t.Run("get", func(t *testing.T) {
		t.Parallel()
		w := httptest.NewRecorder()
		r, err := http.NewRequest(http.MethodGet, pb.PathForAuthDone+"?token=123", nil)
		require.NoError(t, err)

		h(w, r, nil)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("post", func(t *testing.T) {
		t.Parallel()
		params := url.Values{
			"token": {"1123"},
		}

		w := httptest.NewRecorder()
		r, err := http.NewRequest(http.MethodPost,
			pb.PathForAuthDone,
			strings.NewReader(params.Encode()))
		require.NoError(t, err)
		r.Header.Add(header.ContentType, "application/x-www-form-urlencoded")
		h(w, r, nil)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("no_token", func(t *testing.T) {
		t.Parallel()
		w := httptest.NewRecorder()
		r, err := http.NewRequest(http.MethodGet, pb.PathForAuthDone+"?code=123", nil)
		require.NoError(t, err)

		h(w, r, nil)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("error", func(t *testing.T) {
		t.Parallel()
		w := httptest.NewRecorder()
		r, err := http.NewRequest(http.MethodGet, pb.PathForAuthDone+"?error=123&errDescr=message", nil)
		require.NoError(t, err)

		h(w, r, nil)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

func Test_CallbackHandler(t *testing.T) {
	t.Parallel()
	service := testServer.Service(auth.ServiceName).(*auth.Service)
	require.NotNil(t, service)

	h := service.CallbackHandler()

	server := servefiles.New(t)
	server.SetBaseDirs("testdata")
	ctx := context.Background()
	prov, err := service.AuthProvider(ctx, pb.IDP_Github)
	require.NoError(t, err)
	o := prov.Config()
	o.AuthURL = strings.Replace(o.AuthURL, "https://github.com", server.URL(), 1)
	o.TokenURL = strings.Replace(o.TokenURL, "https://github.com", server.URL(), 1)
	require.NotContains(t, o.AuthURL, "https://github.com")
	require.NotContains(t, o.TokenURL, "https://github.com")

	u, err := url.Parse(server.URL() + "/")
	require.NoError(t, err)

	service.BaseURL = u

	t.Run("no_code", func(t *testing.T) {
		t.Parallel()
		w := httptest.NewRecorder()
		r, err := http.NewRequest(http.MethodGet, pb.PathForAuthCallback, nil)
		require.NoError(t, err)

		h(w, r, nil)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, `{"code":"invalid_request","message":"missing state parameter"}`, w.Body.String())
	})

	t.Run("no_state", func(t *testing.T) {
		t.Parallel()
		w := httptest.NewRecorder()
		r, err := http.NewRequest(http.MethodGet, pb.PathForAuthCallback+"?code=abc", nil)
		require.NoError(t, err)

		h(w, r, nil)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, "{\"code\":\"invalid_request\",\"message\":\"missing state parameter\"}", w.Body.String())
	})

	t.Run("bad_state_decode", func(t *testing.T) {
		w := httptest.NewRecorder()
		r, err := http.NewRequest(http.MethodGet, pb.PathForAuthCallback+"?code=abc&state=lll", nil)
		require.NoError(t, err)

		h(w, r, nil)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, `{"code":"invalid_request","message":"failed to decrypt state"}`, w.Body.String())
	})

	t.Run("bad_state_base64", func(t *testing.T) {
		w := httptest.NewRecorder()
		r, err := http.NewRequest(http.MethodGet, pb.PathForAuthCallback+"?code=abc&state=_", nil)
		require.NoError(t, err)

		h(w, r, nil)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, `{"code":"invalid_request","message":"failed to decrypt state"}`, w.Body.String())
	})

	t.Run("token", func(t *testing.T) {
		state, err := service.Protect(context.Background(), &auth.State{
			ResponseType: "token",
			RedirectURL:  "https://localhost:8880/v1/auth",
			Provider:     pb.IDP_Github,
			IssuedAt:     time.Now().Unix(),
		})
		require.NoError(t, err)

		w := httptest.NewRecorder()
		// Value of code is not magic. Mock configured in requests.json will ignore code and give back a token.
		r, err := http.NewRequest(http.MethodGet, pb.PathForAuthCallback+"?code=9298935ecf8777061ff2&state="+state, nil)
		require.NoError(t, err)

		h(w, r, nil)
		require.Equal(t, http.StatusSeeOther, w.Code)
		loc := w.Header().Get("Location")
		assert.NotEmpty(t, loc)
	})
}

func Test_DPoPAuthorizeHandler(t *testing.T) {
	service := testServer.Service(auth.ServiceName).(*auth.Service)
	require.NotNil(t, service)

	//ctx := context.Background()
	h := service.AuthorizeHandler()

	t.Run("no_idp", func(t *testing.T) {
		t.Parallel()
		w := httptest.NewRecorder()

		params := url.Values{
			"client_id": {"trustyca"},
		}
		r, err := http.NewRequest(http.MethodGet, pb.PathForAuthorize+"?"+params.Encode(), nil)
		require.NoError(t, err)

		h(w, r, nil)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, `{"code":"invalid_request","message":"unsupported IDP"}`, w.Body.String())
	})

	t.Run("no_redirect_uri_parameter", func(t *testing.T) {
		t.Parallel()
		w := httptest.NewRecorder()

		params := url.Values{
			"client_id": {"trustyca"},
			"provider":  {pb.IDP_Github.DisplayName()},
		}
		r, err := http.NewRequest(http.MethodGet, pb.PathForAuthorize+"?"+params.Encode(), nil)
		require.NoError(t, err)

		h(w, r, nil)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, `{"code":"invalid_request","message":"missing parameter: redirect_uri"}`, w.Body.String())
	})

	t.Run("invalid_client", func(t *testing.T) {
		t.Parallel()
		w := httptest.NewRecorder()

		params := url.Values{
			"client_id":     {"123"},
			"response_mode": {"query"},
			"response_type": {"code"},
			"scope":         {"email"},
			"redirect_uri":  {"http://localhost:38989"},
			"provider":      {pb.IDP_Github.DisplayName()},
			"nonce":         {"123"},
		}

		r, err := http.NewRequest(http.MethodGet, pb.PathForAuthorize+"?"+params.Encode(), nil)
		require.NoError(t, err)

		h(w, r, nil)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, `{"code":"invalid_request","message":"unsupported client ID: 123"}`, w.Body.String())
	})

	t.Run("invalid_prov", func(t *testing.T) {
		t.Parallel()
		w := httptest.NewRecorder()

		params := url.Values{
			"client_id":     {"trustyca"},
			"response_mode": {"query"},
			"response_type": {"token"},
			"scope":         {"email"},
			"redirect_uri":  {"http://localhost:38989"},
			"provider":      {"SAML123"},
			"nonce":         {"123"},
		}

		r, err := http.NewRequest(http.MethodGet, pb.PathForAuthorize+"?"+params.Encode(), nil)
		require.NoError(t, err)

		h(w, r, nil)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, `{"code":"invalid_request","message":"unsupported IDP"}`, w.Body.String())
	})

	t.Run("invalid_response_type", func(t *testing.T) {
		t.Parallel()
		w := httptest.NewRecorder()

		params := url.Values{
			"client_id":     {"trustyca"},
			"response_mode": {"query"},
			"response_type": {"code"},
			"scope":         {"email"},
			"redirect_uri":  {"http://localhost:38989"},
			"provider":      {"SAML123"},
			"nonce":         {"123"},
		}

		r, err := http.NewRequest(http.MethodGet, pb.PathForAuthorize+"?"+params.Encode(), nil)
		require.NoError(t, err)

		h(w, r, nil)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, `{"code":"invalid_request","message":"unsupported IDP"}`, w.Body.String())
	})

	t.Run("url", func(t *testing.T) {
		t.Parallel()
		w := httptest.NewRecorder()

		params := url.Values{
			"client_id":     {"trustyca"},
			"response_mode": {"query"},
			"response_type": {"token"},
			"scope":         {"email"},
			"redirect_uri":  {"http://localhost:38989"},
			"provider":      {pb.IDP_Github.DisplayName()},
			"nonce":         {"123"},
		}

		r, err := http.NewRequest(http.MethodGet, pb.PathForAuthorize+"?"+params.Encode(), nil)
		require.NoError(t, err)

		h(w, r, nil)
		assert.Equal(t, http.StatusSeeOther, w.Code)
	})
}

func Test_DPoPCallbackHandlerError(t *testing.T) {
	t.Parallel()
	service := testServer.Service(auth.ServiceName).(*auth.Service)
	require.NotNil(t, service)

	h := service.CallbackHandler()

	t.Run("unauthorized", func(t *testing.T) {
		t.Parallel()
		w := httptest.NewRecorder()
		r, err := http.NewRequest(http.MethodGet, pb.PathForAuthCallback+"?error=unauthorized_client&error_description=invalid%20grant", nil)
		require.NoError(t, err)

		h(w, r, nil)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Equal(t, `{"code":"unauthorized_client","message":"OAuth provider error: invalid grant"}`, w.Body.String())
	})

	t.Run("temporarily_unavailable", func(t *testing.T) {
		t.Parallel()
		w := httptest.NewRecorder()
		r, err := http.NewRequest(http.MethodGet, pb.PathForAuthCallback+"?error=temporarily_unavailable&error_description=try%20later", nil)
		require.NoError(t, err)

		h(w, r, nil)
		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
		assert.Equal(t, `{"code":"temporarily_unavailable","message":"OAuth provider error: try later"}`, w.Body.String())
	})

	t.Run("server_error", func(t *testing.T) {
		t.Parallel()
		w := httptest.NewRecorder()
		r, err := http.NewRequest(http.MethodGet, pb.PathForAuthCallback+"?error=server_error&error_description=try%20later", nil)
		require.NoError(t, err)

		h(w, r, nil)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Equal(t, `{"code":"server_error","message":"OAuth provider error: try later"}`, w.Body.String())
	})
}

func Test_DPoPCallbackHandler(t *testing.T) {
	service := testServer.Service(auth.ServiceName).(*auth.Service)
	require.NotNil(t, service)

	ctx := context.Background()
	h := service.CallbackHandler()

	server := servefiles.New(t)
	server.SetBaseDirs("testdata")

	prov, err := service.AuthProvider(ctx, pb.IDP_Google)
	require.NoError(t, err)
	o := prov.Config()
	o.AuthURL = strings.Replace(o.AuthURL, "https://oauth2.googleapis.com", server.URL(), 1)
	o.TokenURL = strings.Replace(o.TokenURL, "https://oauth2.googleapis.com", server.URL(), 1)
	require.NotContains(t, o.AuthURL, "https://oauth2.googleapis.com")
	require.NotContains(t, o.TokenURL, "https://oauth2.googleapis.com")

	u, err := url.Parse(server.URL() + "/")
	require.NoError(t, err)
	service.BaseURL = u

	t.Run("no_code_get", func(t *testing.T) {
		t.Parallel()
		w := httptest.NewRecorder()
		r, err := http.NewRequest(http.MethodGet, pb.PathForAuthCallback+"?state=123", nil)
		require.NoError(t, err)

		h(w, r, nil)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, `{"code":"invalid_request","message":"failed to decrypt state"}`, w.Body.String())
	})

	t.Run("no_state_post", func(t *testing.T) {
		t.Parallel()
		params := url.Values{
			"code": {"1123"},
		}

		w := httptest.NewRecorder()
		r, err := http.NewRequest(http.MethodPost,
			pb.PathForAuthCallback,
			strings.NewReader(params.Encode()))
		require.NoError(t, err)
		r.Header.Add(header.ContentType, "application/x-www-form-urlencoded")

		h(w, r, nil)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, `{"code":"invalid_request","message":"missing state parameter"}`, w.Body.String())
	})

	t.Run("invalid_state_post", func(t *testing.T) {
		t.Parallel()
		params := url.Values{
			"code":  {"1123"},
			"state": {"1123"},
		}

		w := httptest.NewRecorder()
		r, err := http.NewRequest(http.MethodPost,
			pb.PathForAuthCallback,
			strings.NewReader(params.Encode()))
		require.NoError(t, err)
		r.Header.Add(header.ContentType, "application/x-www-form-urlencoded")

		h(w, r, nil)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, `{"code":"invalid_request","message":"failed to decrypt state"}`, w.Body.String())
	})

	idToken, err := service.JwtSigner.Sign(
		ctx,
		jwt.CreateClaims(
			certutil.RandomString(8),
			"admin@trustyca.com",
			service.JwtSigner.Issuer(),
			[]string{"http://localhost:38989"},
			60*time.Minute,
			jwt.MapClaims{
				"sub":            "admin@trustyca.com",
				"picture":        "https://bitly.io/2342134",
				"email_verified": true,
			},
		))
	require.NoError(t, err)

	t.Run("valid_state_post_code_google", func(t *testing.T) {
		t.Parallel()
		st, err := service.Protect(ctx, &auth.State{
			Provider:     pb.IDP_Google,
			ClientID:     "1234",
			Scope:        "email",
			Nonce:        "8245027",
			DPoPJwk:      "1328450198456019",
			Audience:     []string{"http://localhost:38989"},
			RedirectURL:  "http://localhost:38989",
			ResponseType: pb.OAuthResponseTypeCode,
			IssuedAt:     time.Now().Unix(),
		})
		require.NoError(t, err)

		params := url.Values{
			"code":     {"1123"},
			"id_token": {idToken},
			"state":    {st},
		}

		w := httptest.NewRecorder()
		r, err := http.NewRequest(http.MethodPost,
			pb.PathForAuthCallback,
			strings.NewReader(params.Encode()))
		r.Header.Add(header.ContentType, "application/x-www-form-urlencoded")
		require.NoError(t, err)

		h(w, r, nil)
		assert.Equal(t, http.StatusSeeOther, w.Code)
	})

	t.Run("valid_state_post_idtoken_google", func(t *testing.T) {
		t.Parallel()
		st, err := service.Protect(ctx, &auth.State{
			Provider:     pb.IDP_Google,
			ClientID:     "1234",
			Scope:        "email",
			Nonce:        "8245027",
			Audience:     []string{"http://localhost:38989"},
			DPoPJwk:      "82043985620196502917346501962350",
			RedirectURL:  "http://localhost:38989",
			ResponseType: pb.OAuthResponseTypeIDToken,
			IssuedAt:     time.Now().Unix(),
		})
		require.NoError(t, err)

		params := url.Values{
			"code":     {"1123"},
			"id_token": {idToken},
			"state":    {st},
		}

		w := httptest.NewRecorder()
		r, err := http.NewRequest(http.MethodPost,
			pb.PathForAuthCallback,
			strings.NewReader(params.Encode()))
		r.Header.Add(header.ContentType, "application/x-www-form-urlencoded")
		require.NoError(t, err)

		h(w, r, nil)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("valid_state_post_token_google", func(t *testing.T) {
		t.Parallel()
		st, err := service.Protect(ctx, &auth.State{
			Provider:     pb.IDP_Google,
			ClientID:     "1234",
			Scope:        "email",
			Nonce:        "8245027",
			DPoPJwk:      "1328450198456019",
			Audience:     []string{"http://localhost:38989"},
			RedirectURL:  "http://localhost:38989",
			ResponseMode: "form_post",
			ResponseType: "token",
			IssuedAt:     time.Now().Unix(),
		})
		require.NoError(t, err)

		params := url.Values{
			"code":     {"1123"},
			"id_token": {idToken},
			"state":    {st},
		}

		w := httptest.NewRecorder()
		r, err := http.NewRequest(http.MethodPost,
			pb.PathForAuthCallback,
			strings.NewReader(params.Encode()))
		r.Header.Add(header.ContentType, "application/x-www-form-urlencoded")
		require.NoError(t, err)

		h(w, r, nil)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "<title>Submit This Form</title>")
	})

	t.Run("valid_state_post_token_fagment", func(t *testing.T) {
		t.Parallel()
		st, err := service.Protect(ctx, &auth.State{
			Provider:     pb.IDP_Google,
			ClientID:     "1234",
			Scope:        "email",
			Nonce:        "8245027",
			DPoPJwk:      "1328450198456019",
			Audience:     []string{"http://localhost:38989"},
			RedirectURL:  "http://localhost:38989",
			ResponseMode: "fragment",
			ResponseType: "token",
			IssuedAt:     time.Now().Unix(),
		})
		require.NoError(t, err)

		params := url.Values{
			"code":     {"1123"},
			"id_token": {idToken},
			"state":    {st},
		}

		w := httptest.NewRecorder()
		r, err := http.NewRequest(http.MethodPost,
			pb.PathForAuthCallback,
			strings.NewReader(params.Encode()))
		r.Header.Add(header.ContentType, "application/x-www-form-urlencoded")
		require.NoError(t, err)

		h(w, r, nil)
		assert.Equal(t, http.StatusSeeOther, w.Code)
	})

	t.Run("old_state_post_token_fagment", func(t *testing.T) {
		t.Parallel()
		st, err := service.Protect(ctx, &auth.State{
			Provider:     pb.IDP_Google,
			ClientID:     "1234",
			Scope:        "email",
			Nonce:        "8245027",
			DPoPJwk:      "1328450198456019",
			Audience:     []string{"http://localhost:38989"},
			RedirectURL:  "http://localhost:38989",
			ResponseMode: "fragment",
			ResponseType: "token",
			IssuedAt:     time.Now().Add(-6 * time.Minute).Unix(),
		})
		require.NoError(t, err)

		params := url.Values{
			"code":     {"1123"},
			"id_token": {idToken},
			"state":    {st},
		}

		w := httptest.NewRecorder()
		r, err := http.NewRequest(http.MethodPost,
			pb.PathForAuthCallback,
			strings.NewReader(params.Encode()))
		r.Header.Add(header.ContentType, "application/x-www-form-urlencoded")
		require.NoError(t, err)

		h(w, r, nil)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, `{"code":"invalid_request","message":"invalid state"}`, w.Body.String())
	})
}

func Test_DPoPCallbackHandlerGoogle(t *testing.T) {
	service := testServer.Service(auth.ServiceName).(*auth.Service)
	require.NotNil(t, service)

	ctx := context.Background()
	h := service.CallbackHandler()

	server := servefiles.New(t)
	server.SetBaseDirs("testdata")

	prov, err := service.AuthProvider(ctx, pb.IDP_Google)
	require.NoError(t, err)
	o := prov.Config()

	o.AuthURL = strings.Replace(o.AuthURL, "https://login.microsoftonline.com", server.URL(), 1)
	o.TokenURL = strings.Replace(o.TokenURL, "https://login.microsoftonline.com", server.URL(), 1)
	o.UserinfoURL = strings.Replace(o.UserinfoURL, "https://graph.microsoft.com", server.URL(), 1)
	require.NotContains(t, o.AuthURL, "https://login.microsoftonline.com")
	require.NotContains(t, o.TokenURL, "https://login.microsoftonline.com")
	require.NotContains(t, o.UserinfoURL, "https://graph.microsoft.com")

	u, err := url.Parse(server.URL() + "/")
	require.NoError(t, err)
	service.BaseURL = u

	t.Run("valid_state_post_token_google", func(t *testing.T) {
		t.Parallel()
		st, err := service.Protect(ctx, &auth.State{
			Provider:     pb.IDP_Google,
			ClientID:     "1234",
			Scope:        "email",
			Nonce:        "8245027",
			DPoPJwk:      "1328450198456019",
			Audience:     []string{"http://localhost:38989"},
			RedirectURL:  "http://localhost:38989",
			ResponseMode: "form_post",
			ResponseType: "token",
			IssuedAt:     time.Now().Unix(),
		})
		require.NoError(t, err)

		params := url.Values{
			"code":  {"1123"},
			"state": {st},
		}

		w := httptest.NewRecorder()
		r, err := http.NewRequest(http.MethodPost,
			pb.PathForAuthCallback,
			strings.NewReader(params.Encode()))
		r.Header.Add(header.ContentType, "application/x-www-form-urlencoded")
		require.NoError(t, err)

		h(w, r, nil)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "<title>Submit This Form</title>")
	})
}

func Test_DPoPCallbackHandlerLocal(t *testing.T) {
	service := testServer.Service(auth.ServiceName).(*auth.Service)
	require.NotNil(t, service)

	ctx := context.Background()
	h := service.CallbackHandler()

	server := servefiles.New(t)
	server.SetBaseDirs("testdata")

	prov, err := service.AuthProvider(ctx, pb.IDP_Local)
	require.NoError(t, err)
	o := prov.Config()
	o.AuthURL = strings.Replace(o.AuthURL, "https://localhost:8880", server.URL(), 1)

	u, err := url.Parse(server.URL() + "/")
	require.NoError(t, err)
	service.BaseURL = u

	t.Run("valid_state_post_tokenlocal", func(t *testing.T) {
		t.Parallel()
		st, err := service.Protect(ctx, &auth.State{
			Provider:     pb.IDP_Local,
			ClientID:     "1234",
			Scope:        "email",
			Nonce:        "8245027",
			DPoPJwk:      "1328450198456019",
			Audience:     []string{"http://localhost:38989"},
			RedirectURL:  "http://localhost:38989",
			ResponseMode: "query",
			ResponseType: "token",
			IssuedAt:     time.Now().Unix(),
		})
		require.NoError(t, err)

		params := url.Values{
			"code":  {"1123"},
			"state": {st},
		}

		w := httptest.NewRecorder()
		r, err := http.NewRequest(http.MethodPost,
			pb.PathForAuthCallback,
			strings.NewReader(params.Encode()))
		r.Header.Add(header.ContentType, "application/x-www-form-urlencoded")
		require.NoError(t, err)

		h(w, r, nil)
		assert.Equal(t, http.StatusSeeOther, w.Code)
		assert.NotEmpty(t, w.Header().Get(header.Location))
		assert.Empty(t, w.Body.String())
	})
}

func Test_AuthHTTPHandler(t *testing.T) {
	service := testServer.Service(auth.ServiceName).(*auth.Service)
	require.NotNil(t, service)

	t.Run("providers_rpc", func(t *testing.T) {
		t.Parallel()
		w, r, _ := testutils.CreateRequest(http.MethodPost, pb.Auth_GetProviders_FullMethodName, &emptypb.Empty{}, nil)

		service.AuthHTTPHandler()(w, r, nil)
		require.Equal(t, http.StatusOK, w.Code)

		body := w.Body.Bytes()
		var res pb.AuthProvidersResponse
		err := json.Unmarshal(body, &res)
		require.NoError(t, err)
		assert.NotEmpty(t, res.AuthURL)
		assert.NotEmpty(t, res.Providers)
	})
}

func Test_DPoPCallbackHandlerGithub(t *testing.T) {
	t.Parallel()
	service := testServer.Service(auth.ServiceName).(*auth.Service)
	require.NotNil(t, service)

	ctx := context.Background()
	h := service.CallbackHandler()

	server := servefiles.New(t)
	server.SetBaseDirs("testdata")

	prov, err := service.AuthProvider(ctx, pb.IDP_Github)
	require.NoError(t, err)
	o := prov.Config()
	o.AuthURL = strings.Replace(o.AuthURL, "https://github.com", server.URL(), 1)
	o.TokenURL = strings.Replace(o.TokenURL, "https://github.com", server.URL(), 1)
	o.UserinfoURL = strings.Replace(o.UserinfoURL, "https://github.com", server.URL(), 1)
	require.NotContains(t, o.AuthURL, "https://github.com")
	require.NotContains(t, o.TokenURL, "https://github.com")
	require.NotContains(t, o.UserinfoURL, "https://github.com")

	u, err := url.Parse(server.URL() + "/")
	require.NoError(t, err)
	service.BaseURL = u

	t.Run("valid_state_post_token_github", func(t *testing.T) {
		st, err := service.Protect(ctx, &auth.State{
			Provider:     pb.IDP_Github,
			ClientID:     "1234",
			Scope:        "email",
			Nonce:        "8245027",
			DPoPJwk:      "1328450198456019",
			Audience:     []string{"http://localhost:38989"},
			RedirectURL:  "http://localhost:38989",
			ResponseMode: "form_post",
			ResponseType: "token id_token",
			IssuedAt:     time.Now().Unix(),
		})
		require.NoError(t, err)

		params := url.Values{
			"code":  {"1123"},
			"state": {st},
		}

		w := httptest.NewRecorder()
		r, err := http.NewRequest(http.MethodPost,
			pb.PathForAuthCallback,
			strings.NewReader(params.Encode()))
		r.Header.Add(header.ContentType, "application/x-www-form-urlencoded")
		require.NoError(t, err)

		h(w, r, nil)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, `{"code":"invalid_request","message":"unsupported response_type: 'token id_token'"}`, w.Body.String())
	})

	var token string
	// valid_state_get_token_github
	{
		st, err := service.Protect(ctx, &auth.State{
			Provider:     pb.IDP_Github,
			ClientID:     "1234",
			Scope:        "email",
			Nonce:        "8245027",
			DPoPJwk:      "1328450198456019",
			Audience:     []string{"http://localhost:38989"},
			RedirectURL:  "http://localhost:38989",
			ResponseMode: "query",
			ResponseType: "token",
			IssuedAt:     time.Now().Unix(),
		})
		require.NoError(t, err)

		params := url.Values{
			"code":  {"1123"},
			"state": {st},
		}

		w := httptest.NewRecorder()
		r, err := http.NewRequest(http.MethodPost,
			pb.PathForAuthCallback,
			strings.NewReader(params.Encode()))
		r.Header.Add(header.ContentType, "application/x-www-form-urlencoded")
		require.NoError(t, err)

		h(w, r, nil)
		assert.Equal(t, http.StatusSeeOther, w.Code)
		loc := w.Header().Get("Location")
		require.NotEmpty(t, loc)

		u, err := url.Parse(loc)
		require.NoError(t, err)
		token = urlutil.GetValue(u.Query(), "token")
	}
	require.NotEmpty(t, token)

	c := map[string]any{
		"sub":   "1234",
		"email": "test@test.org",
		"role":  "trustyca-admin",
	}
	adminIdn := identity.NewIdentity("trustyca-admin", "10.0.0.1", "", c, token, "DPoP", identity.MethodDPoP)

	t.Run("userinfo", func(t *testing.T) {
		w, r, err := testutils.CreateRequest(http.MethodGet, pb.PathForAuthUserinfo, nil, adminIdn)
		require.NoError(t, err)
		r.Header.Add(header.Authorization, header.DPoP+" "+token)
		_, err = dpop.ForRequest(dpopSigner, r, nil)
		require.NoError(t, err)

		service.UserinfoHandler()(w, r, nil)
		require.Equal(t, http.StatusOK, w.Code)
		require.Equal(t, "application/json", w.Header().Get(header.ContentType))

		body := w.Body.Bytes()
		claims := map[string]any{}
		err = json.Unmarshal(body, &claims)
		require.NoError(t, err)
		assert.Equal(t, "1234", claims["sub"])
		assert.Equal(t, "test@test.org", claims["email"])
	})

	t.Run("userinfo_legacy", func(t *testing.T) {
		w, r, err := testutils.CreateRequest(http.MethodGet, pb.PathForAuthUserinfo, nil, adminIdn)
		require.NoError(t, err)
		r.Header.Add(header.Authorization, header.DPoP+" "+token)
		_, err = dpop.ForRequest(dpopSigner, r, nil)
		require.NoError(t, err)

		service.UserTokenHandler()(w, r, nil)
		require.Equal(t, http.StatusOK, w.Code)
		require.Equal(t, "application/json", w.Header().Get(header.ContentType))

		body := w.Body.Bytes()
		var ti pb.UserTokenResponse
		err = json.Unmarshal(body, &ti)
		require.NoError(t, err)
		assert.Equal(t, "1234", ti.UserInfo.ID)
		assert.Equal(t, "test@test.org", ti.UserInfo.Email)
	})

	t.Run("usertoken_rpc", func(t *testing.T) {
		w, r, err := testutils.CreateRequest(http.MethodGet, pb.Auth_GetUserToken_FullMethodName, &emptypb.Empty{}, adminIdn)
		require.NoError(t, err)
		r.Header.Add(header.Authorization, header.DPoP+" "+token)
		_, err = dpop.ForRequest(dpopSigner, r, nil)
		require.NoError(t, err)

		service.AuthHTTPHandler()(w, r, nil)
		require.Equal(t, http.StatusOK, w.Code)
		require.Equal(t, "application/json", w.Header().Get(header.ContentType))

		body := w.Body.Bytes()
		var ti pb.UserTokenResponse
		err = json.Unmarshal(body, &ti)
		require.NoError(t, err)
		assert.Equal(t, "1234", ti.UserInfo.ID)
		assert.Equal(t, "test@test.org", ti.UserInfo.Email)
	})

	t.Run("caller_rpc", func(t *testing.T) {
		w, r, _ := testutils.CreateRequest(http.MethodPost, pb.Auth_Caller_FullMethodName, &emptypb.Empty{}, adminIdn)
		r.Header.Add(header.Authorization, header.DPoP+" "+token)

		_, err = dpop.ForRequest(dpopSigner, r, nil)
		require.NoError(t, err)

		service.AuthHTTPHandler()(w, r, nil)
		require.Equal(t, http.StatusOK, w.Code)

		body := w.Body.Bytes()
		var res pb.CallerStatusResponse
		err = json.Unmarshal(body, &res)
		require.NoError(t, err)
		assert.Equal(t, "10.0.0.1", res.Subject)
		assert.Equal(t, "trustyca-admin", res.Role)
	})
}

func Test_RequestValidate(t *testing.T) {
	t.Parallel()
	r := auth.Request{
		ResponseType: "rt",
	}
	assert.EqualError(t, r.Validate(), "invalid_request: unsupported response_type: 'rt'")
	r = auth.Request{
		ResponseType: "token",
	}
	assert.EqualError(t, r.Validate(), "invalid_request: missing parameter: redirect_uri")
	r = auth.Request{
		ResponseType: "token",
		RedirectURI:  "http://localhost:8880/v1/auth/callback",
	}
	assert.EqualError(t, r.Validate(), "invalid_request: missing parameter: scope")
	r = auth.Request{
		ResponseType: "token",
		RedirectURI:  "http://localhost:8880/v1/auth/callback",
		Scope:        "email",
	}
	assert.NoError(t, r.Validate())
	r = auth.Request{
		ResponseType: "token",
		RedirectURI:  "http://localhost:8880/v1/auth/callback",
		Scope:        "email",
		Provider:     pb.IDP_Github,
	}
	assert.NoError(t, r.Validate())
}

func Test_TenantHandler(t *testing.T) {
	t.Setenv("TRUSTYCA_GOOGLE_CLIENT_ID", "testclientid")
	t.Setenv("TRUSTYCA_GOOGLE_CLIENT_SECRET", "testclientsecret")

	service := testServer.Service(auth.ServiceName).(*auth.Service)
	require.NotNil(t, service)

	ctx := context.Background()
	h := service.CallbackHandler()

	server := servefiles.New(t)
	server.SetBaseDirs("testdata")
	prov, err := service.AuthProvider(ctx, pb.IDP_Google)
	require.NoError(t, err)
	o := prov.Config()

	o.AuthURL = server.URL() + "/o/oauth2/v2/auth"
	o.TokenURL = server.URL() + "/token"
	u, err := url.Parse(server.URL() + "/")
	require.NoError(t, err)
	service.BaseURL = u

	idToken, err := service.JwtSigner.Sign(
		ctx,
		jwt.CreateClaims(
			certutil.RandomString(8),
			"admin@trustyca.com",
			service.JwtSigner.Issuer(),
			[]string{"http://localhost:38989"},
			60*time.Minute,
			jwt.MapClaims{
				"sub":            "admin@trustyca.com",
				"picture":        "https://bitly.io/2342134",
				"email_verified": true,
			},
		))
	require.NoError(t, err)

	var accessToken string

	t.Run("valid_state_post_code_google", func(t *testing.T) {
		st, err := service.Protect(ctx, &auth.State{
			Provider:     pb.IDP_Google,
			ClientID:     "1234",
			Scope:        "email",
			Nonce:        "8245027",
			DPoPJwk:      "1328450198456019",
			Audience:     []string{"http://localhost:38989"},
			RedirectURL:  "http://localhost:38989",
			ResponseType: pb.OAuthResponseTypeToken,
			IssuedAt:     time.Now().Unix(),
		})
		require.NoError(t, err)

		params := url.Values{
			"code":     {"1123"},
			"id_token": {idToken},
			"state":    {st},
		}

		w := httptest.NewRecorder()
		r, err := http.NewRequest(http.MethodPost,
			pb.PathForAuthCallback,
			strings.NewReader(params.Encode()))
		r.Header.Add(header.ContentType, "application/x-www-form-urlencoded")
		require.NoError(t, err)

		h(w, r, nil)
		require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
		loc := w.Header().Get("Location")
		require.NotEmpty(t, loc)

		u, err := url.Parse(loc)
		require.NoError(t, err)
		accessToken = urlutil.GetQueryString(u, "token")
		require.NotEmpty(t, accessToken)
	})

	require.NotEmpty(t, accessToken)

	inClaims, err := service.JwtParser.ParseToken(ctx, accessToken, nil)
	require.NoError(t, err)

	var claims jwt.Claims
	err = inClaims.To(&claims)
	require.NoError(t, err)
	assert.NotEmpty(t, claims.Subject)

	t.Run("usertoken", func(t *testing.T) {
		w := httptest.NewRecorder()
		r, _ := http.NewRequest(http.MethodGet, pb.PathForAuthUserinfo, nil)
		require.NoError(t, err)

		c := map[string]any{
			"sub":   claims.Subject,
			"email": claims.Email,
		}
		r = identity.WithTestIdentity(r, identity.NewIdentity("admin", "10.0.0.1", "", c, accessToken, "Bearer", identity.MethodJWT))

		service.UserTokenHandler()(w, r, nil)
		require.Equal(t, http.StatusOK, w.Code)
		require.Equal(t, "application/json", w.Header().Get(header.ContentType))

		body := w.Body.Bytes()
		var ti pb.UserTokenResponse
		err = json.Unmarshal(body, &ti)
		require.NoError(t, err)
		assert.Equal(t, claims.Subject, ti.UserInfo.ID)
		assert.NotEmpty(t, claims.Email, ti.UserInfo.Email)
	})
}

func TestCallerStatusGrpc(t *testing.T) {
	t.Parallel()
	res, err := authClient.Caller(context.Background(), &emptypb.Empty{})
	require.NoError(t, err)

	assert.Equal(t, identity.GuestRoleName, res.Role)
}

func TestCallerStatusHttp(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()
	client, err := retriable.Default(httpAddr)
	require.NoError(t, err)

	ctx := retriable.WithHeaders(context.Background(), textContentHeaders)

	hdr, _, err := client.Get(ctx, pb.PathForStatusCaller, w)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, w.Code)
	// TODO: add Print
	//assert.Contains(t, hdr.Get(header.ContentType), header.TextPlain)
	assert.Contains(t, hdr.Get(header.ContentType), header.ApplicationJSON)
}

func TestCallerStatusHttpJSON(t *testing.T) {
	t.Parallel()
	res := new(pb.CallerStatusResponse)
	client, err := retriable.Default(httpAddr)
	require.NoError(t, err)
	ctx := retriable.WithHeaders(context.Background(), jsonContentHeaders)

	hdr, sc, err := client.Get(ctx, pb.PathForStatusCaller, res)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, sc)
	assert.Contains(t, hdr.Get(header.ContentType), header.ApplicationJSON)
	assert.NotEmpty(t, res.Role)
}
