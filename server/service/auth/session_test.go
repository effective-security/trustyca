package auth_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/effective-security/porto/restserver"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/identity"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/authctx"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/server/service/auth"
	"github.com/effective-security/trustyca/tests/testutils"
	"github.com/effective-security/xpki/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sessionIdentity returns the identity of a signed-in user whose token is
// valid for an hour, authenticated by the auth cookie or the Authorization
// header (method)
func sessionIdentity(user *model.User, orgID string, method identity.AuthMethod) identity.Identity {
	now := time.Now()
	claims := map[string]any{
		"sub":   user.ID.String(),
		"email": user.Email,
		"jti":   testDb.NextID().String(),
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	}
	if orgID != "" {
		claims[authctx.ClaimOrg] = orgID
	}
	return identity.NewIdentity("user", user.ID.String(), orgID, claims, "session-token", header.Bearer, method)
}

// responseCookies returns the cookies the response sets, by name
func responseCookies(w *httptest.ResponseRecorder) map[string]*http.Cookie {
	res := map[string]*http.Cookie{}
	for _, c := range w.Result().Cookies() {
		res[c.Name] = c
	}
	return res
}

// requireAuthCookie checks the attributes of the auth cookie: the browser
// sends it to every host of the cookie domain, never to a script
func requireAuthCookie(t *testing.T, c *http.Cookie) {
	t.Helper()
	require.NotEmpty(t, c.Value)
	assert.True(t, c.HttpOnly)
	assert.True(t, c.Secure)
	assert.Equal(t, http.SameSiteNoneMode, c.SameSite)
	assert.Equal(t, "/", c.Path)
	assert.Equal(t, testCookies.Domain, "."+c.Domain)
}

// requireCSRFCookie checks the attributes of the CSRF cookie: a script of
// the console reads it and sends it back in the X-CSRF-Token header
func requireCSRFCookie(t *testing.T, c *http.Cookie) {
	t.Helper()
	assert.Len(t, c.Value, 32)
	assert.False(t, c.HttpOnly)
	assert.True(t, c.Secure)
	assert.Equal(t, http.SameSiteNoneMode, c.SameSite)
	assert.Equal(t, testCookies.Domain, "."+c.Domain)
}

// requireExpiredCookies checks that the response removes both cookies
func requireExpiredCookies(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	cookies := responseCookies(w)
	for _, name := range []string{testCookies.Auth, testCookies.CSRF} {
		c := cookies[name]
		require.NotNil(t, c, name)
		assert.Negative(t, c.MaxAge, name)
		assert.True(t, c.Secure, name)
		assert.Equal(t, testCookies.Domain, "."+c.Domain, name)
	}
	assert.Empty(t, cookies[testCookies.Auth].Value)
}

func Test_AuthOrgHandler(t *testing.T) {
	t.Parallel()
	service := testServer.Service(auth.ServiceName).(*auth.Service)

	owner, first := newOwnerOrg(t)
	second, err := testDb.RegisterOrg(t.Context(), &model.Org{
		Name:   "Second " + owner.ID.String(),
		Status: pb.ItemStatus_Active,
	}, owner.ID.UInt64())
	require.NoError(t, err)
	deleteOrgOnCleanup(t, second.ID)
	_, other := newOwnerOrg(t)

	post := func(t *testing.T, idn identity.Identity, req *pb.SelectOrgRequest) *httptest.ResponseRecorder {
		t.Helper()
		w, r, err := testutils.CreateRequest(http.MethodPost, pb.PathForAuthOrg, req, idn)
		require.NoError(t, err)
		if idn != nil && idn.AuthMethod() == identity.MethodJWT {
			r.Header.Set(header.Authorization, header.Bearer+" "+idn.AccessToken())
		}
		service.AuthOrgHandler()(w, r, nil)
		return w
	}
	decode := func(t *testing.T, w *httptest.ResponseRecorder) *pb.UserTokenResponse {
		t.Helper()
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		var res pb.UserTokenResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &res))
		return &res
	}

	t.Run("cookie_remember_me", func(t *testing.T) {
		t.Parallel()
		w := post(t, sessionIdentity(owner, first.ID.String(), identity.MethodJWTCookie),
			&pb.SelectOrgRequest{OrgID: second.ID.String(), RememberMe: true})
		res := decode(t, w)
		// the token is in the HttpOnly cookie only
		assert.Empty(t, res.Token.AccessToken)
		assert.Equal(t, second.ID.String(), res.UserInfo.OrgID)
		assert.Equal(t, pb.Role_Owner.String(), res.UserInfo.OrgRole)

		cookies := responseCookies(w)
		authCookie := cookies[testCookies.Auth]
		require.NotNil(t, authCookie)
		requireAuthCookie(t, authCookie)
		// until the token expires, which keeps the expiry of the session
		assert.Positive(t, authCookie.MaxAge)
		assert.LessOrEqual(t, authCookie.MaxAge, int(time.Hour.Seconds()))

		csrf := cookies[testCookies.CSRF]
		require.NotNil(t, csrf)
		requireCSRFCookie(t, csrf)

		claims := parseClaims(t, service, authCookie.Value)
		assert.Equal(t, second.ID.String(), claims.String(authctx.ClaimOrg))
		assert.Equal(t, pb.Role_Owner.String(), claims.String(authctx.ClaimOrgRole))
		assert.Equal(t, owner.ID.String(), claims.String("sub"))
	})

	t.Run("cookie_session", func(t *testing.T) {
		t.Parallel()
		w := post(t, sessionIdentity(owner, second.ID.String(), identity.MethodJWTCookie),
			&pb.SelectOrgRequest{OrgID: first.ID.String()})
		res := decode(t, w)
		assert.Empty(t, res.Token.AccessToken)
		assert.Equal(t, first.ID.String(), res.UserInfo.OrgID)

		// without RememberMe the cookies end with the browser session
		cookies := responseCookies(w)
		authCookie := cookies[testCookies.Auth]
		require.NotNil(t, authCookie)
		requireAuthCookie(t, authCookie)
		assert.Zero(t, authCookie.MaxAge)
		assert.True(t, authCookie.Expires.IsZero())
		require.NotNil(t, cookies[testCookies.CSRF])
		assert.Zero(t, cookies[testCookies.CSRF].MaxAge)
		assert.Equal(t, first.ID.String(), parseClaims(t, service, authCookie.Value).String(authctx.ClaimOrg))
	})

	t.Run("bearer", func(t *testing.T) {
		t.Parallel()
		w := post(t, sessionIdentity(owner, first.ID.String(), identity.MethodJWT),
			&pb.SelectOrgRequest{OrgID: second.ID.String(), RememberMe: true})
		res := decode(t, w)
		// a caller with the Authorization header keeps the token, and its
		// cookies are not replaced
		require.NotEmpty(t, res.Token.AccessToken)
		assert.Equal(t, second.ID.String(), parseClaims(t, service, res.Token.AccessToken).String(authctx.ClaimOrg))
		assert.Empty(t, w.Result().Cookies())
	})

	t.Run("no_access", func(t *testing.T) {
		t.Parallel()
		w := post(t, sessionIdentity(owner, first.ID.String(), identity.MethodJWTCookie),
			&pb.SelectOrgRequest{OrgID: other.ID.String()})
		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Contains(t, w.Body.String(), "no access to the requested organization")
		assert.Empty(t, w.Result().Cookies())
	})

	t.Run("guest", func(t *testing.T) {
		t.Parallel()
		w := post(t, nil, &pb.SelectOrgRequest{OrgID: first.ID.String()})
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Empty(t, w.Result().Cookies())
	})

	t.Run("invalid_org", func(t *testing.T) {
		t.Parallel()
		w := post(t, sessionIdentity(owner, first.ID.String(), identity.MethodJWTCookie),
			&pb.SelectOrgRequest{OrgID: "not-an-id"})
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Empty(t, w.Result().Cookies())
	})
}

func Test_SelectOrg_CookieSession(t *testing.T) {
	t.Parallel()
	service := testServer.Service(auth.ServiceName).(*auth.Service)
	owner, org := newOwnerOrg(t)

	ctxOf := func(method identity.AuthMethod) *http.Request {
		_, r, err := testutils.CreateRequest(http.MethodPost, pb.Auth_SelectOrg_FullMethodName, nil,
			sessionIdentity(owner, "", method))
		require.NoError(t, err)
		return r
	}

	// gRPC cannot set the cookie: a cookie session gets no token
	res, err := service.SelectOrg(ctxOf(identity.MethodJWTCookie).Context(), &pb.SelectOrgRequest{OrgID: org.ID.String()})
	require.NoError(t, err)
	assert.Empty(t, res.Token.AccessToken)
	assert.Equal(t, org.ID.String(), res.UserInfo.OrgID)

	res, err = service.SelectOrg(ctxOf(identity.MethodJWT).Context(), &pb.SelectOrgRequest{OrgID: org.ID.String()})
	require.NoError(t, err)
	require.NotEmpty(t, res.Token.AccessToken)
	assert.Equal(t, org.ID.String(), parseClaims(t, service, res.Token.AccessToken).String(authctx.ClaimOrg))
}

func Test_RevokeTokenHandler_Cookies(t *testing.T) {
	// replaces the revocation of the shared parser: not parallel
	service := testServer.Service(auth.ServiceName).(*auth.Service)
	owner, org := newOwnerOrg(t)

	orig := service.JwtParser.GetRevocation()
	rev := &fakeRevocation{}
	service.JwtParser.SetRevocation(rev)
	t.Cleanup(func() { service.JwtParser.SetRevocation(orig) })

	idn := sessionIdentity(owner, org.ID.String(), identity.MethodJWTCookie)
	w, r, err := testutils.CreateRequest(http.MethodDelete, pb.Auth_RevokeToken_FullMethodName, nil, idn)
	require.NoError(t, err)
	service.RevokeTokenHandler()(w, r, nil)
	assert.Equal(t, http.StatusNoContent, w.Code, w.Body.String())
	assert.Equal(t, []string{idn.Claims().String("jti")}, rev.revoked)
	requireExpiredCookies(t, w)

	// a guest has nothing to revoke, and its cookies are removed
	w, r, err = testutils.CreateRequest(http.MethodDelete, pb.Auth_RevokeToken_FullMethodName, nil, nil)
	require.NoError(t, err)
	service.RevokeTokenHandler()(w, r, nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "no token to revoke")
	requireExpiredCookies(t, w)
	assert.Len(t, rev.revoked, 1)

	// a failed revocation still removes the cookies
	w, r, err = testutils.CreateRequest(http.MethodDelete, pb.Auth_RevokeToken_FullMethodName, nil,
		sessionIdentity(owner, org.ID.String(), identity.MethodJWTCookie))
	require.NoError(t, err)
	service.JwtParser.SetRevocation(nil)
	service.RevokeTokenHandler()(w, r, nil)
	assert.Equal(t, http.StatusNotImplemented, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "revocation not supported")
	requireExpiredCookies(t, w)
}

func Test_RevokeTokenHandler_SignOut(t *testing.T) {
	t.Parallel()
	service := testServer.Service(auth.ServiceName).(*auth.Service)

	email := newEmail()
	deleteUserOnCleanup(t, email)
	w := localLogin(t, service, url.Values{
		"idpuser.email": {"local+" + email},
		"redirect_uri":  {consoleRedirect},
		"response_type": {pb.OAuthResponseTypeToken},
	})
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	loc, err := url.Parse(w.Header().Get(header.Location))
	require.NoError(t, err)
	token := loc.Query().Get(pb.OAuthResponseTypeToken)
	claims := parseClaims(t, service, token)
	deleteDefaultOrgOnCleanup(t, claims)

	// the cookie session signs out with the revocation of the container
	idn := identity.NewIdentity("user", claims.String("sub"), claims.String(authctx.ClaimOrg),
		claims, token, header.Bearer, identity.MethodJWTCookie)
	w, r, err := testutils.CreateRequest(http.MethodDelete, pb.Auth_RevokeToken_FullMethodName, nil, idn)
	require.NoError(t, err)
	service.RevokeTokenHandler()(w, r, nil)
	assert.Equal(t, http.StatusNoContent, w.Code, w.Body.String())
	requireExpiredCookies(t, w)

	// a copy of the cookie is refused from now on
	_, err = service.JwtParser.ParseToken(t.Context(), token, &jwt.VerifyConfig{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token revoked")
}

func Test_RemoveCookieHandler(t *testing.T) {
	t.Parallel()
	service := testServer.Service(auth.ServiceName).(*auth.Service)

	w, r, err := testutils.CreateRequest(http.MethodDelete, pb.PathForRemoveCookie, nil, nil)
	require.NoError(t, err)
	service.RemoveCookieHandler()(w, r, nil)
	assert.Equal(t, http.StatusNoContent, w.Code)
	requireExpiredCookies(t, w)
}

func Test_RegisterRoute_Session(t *testing.T) {
	t.Parallel()
	service := testServer.Service(auth.ServiceName).(*auth.Service)

	router := restserver.NewRouter(http.NotFound)
	service.RegisterRoute(router)
	h := router.Handler()

	tcs := []struct {
		method, path string
		req          any
		want         int
	}{
		// the org switch of a cookie session: a guest is refused by the
		// handler, not by the router
		{method: http.MethodPost, path: pb.PathForAuthOrg, req: &pb.SelectOrgRequest{OrgID: "1234"}, want: http.StatusUnauthorized},
		// a GET would sign a cookie session out without the CSRF check
		{method: http.MethodGet, path: pb.Auth_RevokeToken_FullMethodName, want: http.StatusMethodNotAllowed},
		{method: http.MethodDelete, path: pb.PathForRemoveCookie, want: http.StatusNoContent},
	}
	for _, tc := range tcs {
		w, r, err := testutils.CreateRequest(tc.method, tc.path, tc.req, nil)
		require.NoError(t, err)
		h.ServeHTTP(w, r)
		assert.Equal(t, tc.want, w.Code, "%s %s: %s", tc.method, tc.path, w.Body.String())
	}
}
