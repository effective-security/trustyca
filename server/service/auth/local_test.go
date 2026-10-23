package auth_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/authctx"
	"github.com/effective-security/trustyca/internal/config"
	"github.com/effective-security/trustyca/server/service/auth"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xpki/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// apiHost is the wfe under the dev cookie domain, the host the console
	// in cookie mode starts its login on
	apiHost = "api.local.trustyca.io:8880"
	// consoleRedirect is the landing page of the console, in
	// auth.allowed_redirect_domains of the dev configuration
	consoleRedirect = "https://app.local.trustyca.io:4200/auth/authenticated"
)

// authorizeURL returns the authorize URL on apiHost with the parameters
func authorizeURL(params url.Values) string {
	return "https://" + apiHost + pb.PathForAuthorize + "?" + params.Encode()
}

// localLogin runs the login of the local provider through the authorize
// and callback handlers, as a browser follows the redirects, and returns
// the response of the callback
func localLogin(t *testing.T, service *auth.Service, params url.Values) *httptest.ResponseRecorder {
	t.Helper()

	w := httptest.NewRecorder()
	service.AuthorizeHandler()(w, httptest.NewRequest(http.MethodGet, authorizeURL(params), nil), nil)
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())

	// the local provider has no IdP: the authorize end-point sends the
	// browser to the callback on the host it was called on
	loc, err := url.Parse(w.Header().Get(header.Location))
	require.NoError(t, err)
	assert.Equal(t, "https", loc.Scheme)
	assert.Equal(t, apiHost, loc.Host)
	assert.Equal(t, pb.PathForAuthCallback, loc.Path)
	assert.Equal(t, "local", loc.Query().Get("code"))
	require.NotEmpty(t, loc.Query().Get("state"))

	w = httptest.NewRecorder()
	service.CallbackHandler()(w, httptest.NewRequest(http.MethodGet, loc.String(), nil), nil)
	return w
}

// parseClaims verifies the token the service signed and returns its claims
func parseClaims(t *testing.T, service *auth.Service, token string) jwt.MapClaims {
	t.Helper()
	claims, err := service.JwtParser.ParseToken(t.Context(), token, &jwt.VerifyConfig{})
	require.NoError(t, err)
	return claims
}

// deleteDefaultOrgOnCleanup removes the default org the login of a new
// user created, named in the org claim of its token
func deleteDefaultOrgOnCleanup(t *testing.T, claims jwt.MapClaims) {
	t.Helper()
	orgID, err := xdb.ParseID(claims.String(authctx.ClaimOrg))
	require.NoError(t, err)
	deleteOrgOnCleanup(t, orgID)
}

func Test_LocalProvider_Providers(t *testing.T) {
	t.Parallel()
	service := testServer.Service(auth.ServiceName).(*auth.Service)

	// the prefix selects the local provider, without an invitation
	res, err := service.GetProviders(t.Context(), &pb.AuthProvidersRequest{Email: "local+" + newEmail()})
	require.NoError(t, err)
	assert.Equal(t, []string{"local"}, res.ProviderNames)
	assert.Equal(t, []pb.IDP_Enum{pb.IDP_Local}, res.Providers)
}

func Test_LocalProvider_Token(t *testing.T) {
	t.Parallel()
	service := testServer.Service(auth.ServiceName).(*auth.Service)

	email := newEmail()
	deleteUserOnCleanup(t, email)

	params := url.Values{
		"idpuser.email": {"local+" + email},
		"redirect_uri":  {consoleRedirect},
		"response_type": {pb.OAuthResponseTypeToken},
		"response_mode": {"query"},
	}
	w := localLogin(t, service, params)
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())

	loc, err := url.Parse(w.Header().Get(header.Location))
	require.NoError(t, err)
	assert.Equal(t, consoleRedirect, loc.Scheme+"://"+loc.Host+loc.Path)
	token := loc.Query().Get(pb.OAuthResponseTypeToken)
	require.NotEmpty(t, token)

	// the address is signed in without the prefix
	claims := parseClaims(t, service, token)
	deleteDefaultOrgOnCleanup(t, claims)
	assert.Equal(t, email, claims.String("email"))
	assert.Equal(t, strings.TrimSuffix(email, "@example.com"), claims.String("name"))
	// the claim holds the number of the enum
	assert.Equal(t, pb.IDP_Local, pb.IDPFromString(claims.String("provider")))
	subject := claims.String("sub")
	require.NotEmpty(t, subject)

	user, err := testDb.GetUserByEmail(t.Context(), email)
	require.NoError(t, err)
	assert.Equal(t, user.ID.String(), subject)

	// a second login of the address is the same user, in the same org
	w = localLogin(t, service, params)
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	loc, err = url.Parse(w.Header().Get(header.Location))
	require.NoError(t, err)
	again := parseClaims(t, service, loc.Query().Get(pb.OAuthResponseTypeToken))
	assert.Equal(t, subject, again.String("sub"))
	assert.Equal(t, claims.String(authctx.ClaimOrg), again.String(authctx.ClaimOrg))
}

func Test_LocalProvider_Cookie(t *testing.T) {
	t.Parallel()
	service := testServer.Service(auth.ServiceName).(*auth.Service)

	email := newEmail()
	deleteUserOnCleanup(t, email)

	w := localLogin(t, service, url.Values{
		"idpuser.email": {"local+" + email},
		"redirect_uri":  {consoleRedirect},
		"response_type": {pb.OAuthResponseTypeCookie},
		"response_mode": {"query"},
		"remember_me":   {"true"},
	})
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())

	// the console learns the name of the CSRF cookie, never the token
	loc, err := url.Parse(w.Header().Get(header.Location))
	require.NoError(t, err)
	q := loc.Query()
	assert.Equal(t, "true", q.Get("cookie_set"))
	assert.Equal(t, testCookies.CSRF, q.Get("csrf"))
	assert.NotEmpty(t, q.Get("expires_in"))
	assert.False(t, q.Has(pb.OAuthResponseTypeToken))
	assert.False(t, q.Has(pb.OAuthResponseTypeCode))

	cookies := responseCookies(w)
	authCookie := cookies[testCookies.Auth]
	require.NotNil(t, authCookie)
	requireAuthCookie(t, authCookie)
	// remember_me keeps the cookie until the token expires
	assert.Positive(t, authCookie.MaxAge)

	csrf := cookies[testCookies.CSRF]
	require.NotNil(t, csrf)
	requireCSRFCookie(t, csrf)
	assert.Equal(t, authCookie.MaxAge, csrf.MaxAge)

	claims := parseClaims(t, service, authCookie.Value)
	deleteDefaultOrgOnCleanup(t, claims)
	assert.Equal(t, email, claims.String("email"))
	assert.Equal(t, pb.Role_Owner.String(), claims.String(authctx.ClaimOrgRole))
}

func Test_LocalProvider_NotLocal(t *testing.T) {
	// changes the environment of the shared configuration: not parallel
	service := testServer.Service(auth.ServiceName).(*auth.Service)
	ctx := t.Context()

	// a state the authorize end-point of a local instance issued
	st, err := service.Protect(ctx, &auth.State{
		Provider:     pb.IDP_Local,
		Email:        newEmail(),
		RedirectURL:  consoleRedirect,
		ResponseMode: "query",
		ResponseType: pb.OAuthResponseTypeToken,
		IssuedAt:     time.Now().Unix(),
	})
	require.NoError(t, err)

	env := testCfg.Service.Environment
	testCfg.Service.Environment = config.EnvironmentDev
	t.Cleanup(func() { testCfg.Service.Environment = env })

	// the prefix is an ordinary address, of a user nobody invited
	_, err = service.GetProviders(ctx, &pb.AuthProvidersRequest{Email: "local+" + newEmail()})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "login is restricted to invited users only")

	for _, params := range []url.Values{
		{"provider": {"local"}},
		{"idpuser.email": {"local+" + newEmail()}},
	} {
		params.Set("redirect_uri", consoleRedirect)
		w := httptest.NewRecorder()
		service.AuthorizeHandler()(w, httptest.NewRequest(http.MethodGet, authorizeURL(params), nil), nil)
		assert.Equal(t, http.StatusBadRequest, w.Code, params.Encode())
		assert.Contains(t, w.Body.String(), "unsupported IDP", params.Encode())
	}

	cb := url.Values{
		"code":  {"local"},
		"state": {st},
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "https://"+apiHost+pb.PathForAuthCallback+"?"+cb.Encode(), nil)
	service.CallbackHandler()(w, r, nil)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "unsupported provider: Local")
}
