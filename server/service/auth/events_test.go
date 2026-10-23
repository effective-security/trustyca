package auth_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/identity"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/authctx"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/server/service/auth"
	"github.com/effective-security/x/urlutil"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/dataprotection"
	"github.com/effective-security/xpki/jwt"
	"github.com/effective-security/xpki/jwt/oauth2client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/emptypb"
)

const (
	// eventWait bounds the wait for an event: TryCreateEvent writes it in
	// the background
	eventWait = 5 * time.Second
	eventTick = 20 * time.Millisecond
	// dateHeader carries the timestamp an API key signs
	dateHeader = "Date"
)

// wantEvent holds the fields of an expected event that the query used to
// find it does not already fix
type wantEvent struct {
	OrgID       uint64
	ProjectID   uint64
	Email       string
	Title       string
	Description string
}

// waitEvents waits until the query finds count events and returns them,
// newest first
func waitEvents(t *testing.T, req *query.ListEventsRequest, count int) model.EventSlice {
	t.Helper()
	req.Limit = 10
	var rows model.EventSlice
	require.Eventually(t, func() bool {
		res, err := testDb.ListEvents(context.Background(), req)
		if err != nil {
			return false
		}
		rows = res.Rows
		return len(rows) >= count
	}, eventWait, eventTick, "%s events of %d", req.Type, req.ReferenceID)
	require.Len(t, rows, count)
	return rows
}

// waitEvent waits for the one event of the type that references refID
func waitEvent(t *testing.T, typ pb.EventType_Enum, refID xdb.ID) *model.Event {
	t.Helper()
	return waitEvents(t, &query.ListEventsRequest{Type: typ, ReferenceID: refID.UInt64()}, 1)[0]
}

// requireEvent checks the event fields, and that the auth service emitted it
func requireEvent(t *testing.T, want wantEvent, evt *model.Event) {
	t.Helper()
	assert.Equal(t, want, wantEvent{
		OrgID:       evt.OrgID.UInt64(),
		ProjectID:   evt.ProjectID.UInt64(),
		Email:       evt.Email.String(),
		Title:       evt.Title,
		Description: evt.Description.String(),
	})
	assert.Equal(t, auth.ServiceName, evt.Source.String())
}

// newEmail returns an email address no other test uses
func newEmail() string {
	return testDb.NextID().String() + "@example.com"
}

// deleteUserOnCleanup removes the user and logins of the email when the
// test ends
func deleteUserOnCleanup(t *testing.T, email string) {
	t.Cleanup(func() {
		_, err := testDb.DeleteUserByEmail(context.Background(), email)
		assert.NoError(t, err)
	})
}

// deleteOrgOnCleanup removes the org with its projects, members and events
// when the test ends
func deleteOrgOnCleanup(t *testing.T, orgID xdb.ID) {
	t.Cleanup(func() {
		_, err := testDb.DeleteOrg(context.Background(), orgID.UInt64())
		assert.NoError(t, err)
	})
}

// newOwnerOrg registers a user and an active org the user owns, both
// removed when the test ends
func newOwnerOrg(t *testing.T) (*model.User, *model.Org) {
	t.Helper()
	ctx := t.Context()
	email := newEmail()
	_, owner, err := testDb.LoginUser(ctx, &model.Login{
		ExternalID: email,
		Name:       "Events Owner",
		Email:      email,
		Provider:   pb.IDP_Github,
	})
	require.NoError(t, err)
	deleteUserOnCleanup(t, email)

	org, err := testDb.RegisterOrg(ctx, &model.Org{
		Name:   "Events " + owner.ID.String(),
		Status: pb.ItemStatus_Active,
	}, owner.ID.UInt64())
	require.NoError(t, err)
	deleteOrgOnCleanup(t, org.ID)
	return owner, org
}

// newProject registers an active project in the org
func newProject(t *testing.T, orgID xdb.ID) *model.Project {
	t.Helper()
	project, err := testDb.RegisterProject(t.Context(), &model.Project{
		OrgID:  orgID,
		Name:   "Events",
		Status: pb.ItemStatus_Active,
	})
	require.NoError(t, err)
	return project
}

// tokenCtx returns the context of a request authenticated with a token
// with the claims, as the wfe server builds it
func tokenCtx(subject, orgID string, claims map[string]any) context.Context {
	idn := identity.NewIdentity("user", subject, orgID, claims, "token", "Bearer", identity.MethodJWT)
	rctx := identity.NewRequestContext(idn, pb.PathForAuth)
	return authctx.NewTrustyCtx(identity.AddToContext(context.Background(), rctx), rctx)
}

// fakeRevocation accepts every token and records the IDs of the revoked
// ones
type fakeRevocation struct {
	revoked []string
}

func (r *fakeRevocation) Validate(context.Context, string, jwt.MapClaims) error {
	return nil
}

func (r *fakeRevocation) Revoke(_ context.Context, _ string, claims jwt.MapClaims) error {
	r.revoked = append(r.revoked, claims.String("jti"))
	return nil
}

func Test_SelectOrg_Event(t *testing.T) {
	t.Parallel()
	service := testServer.Service(auth.ServiceName).(*auth.Service)
	owner, org := newOwnerOrg(t)

	ctx := tokenCtx(owner.ID.String(), "", map[string]any{
		"sub":   owner.ID.String(),
		"email": owner.Email,
	})
	res, err := service.SelectOrg(ctx, &pb.SelectOrgRequest{OrgID: org.ID.String()})
	require.NoError(t, err)
	assert.Equal(t, org.ID.String(), res.UserInfo.OrgID)

	requireEvent(t, wantEvent{
		OrgID:       org.ID.UInt64(),
		Email:       owner.Email,
		Title:       "User signed in",
		Description: owner.Email + " signed in as Owner",
	}, waitEvent(t, pb.EventType_UserSignedIn, owner.ID))
}

func Test_RevokeToken_Events(t *testing.T) {
	// replaces the revocation of the shared parser: not parallel
	service := testServer.Service(auth.ServiceName).(*auth.Service)
	owner, org := newOwnerOrg(t)
	project := newProject(t, org.ID)

	userJTI := testDb.NextID().String()
	ctx := tokenCtx(owner.ID.String(), org.ID.String(), map[string]any{
		"sub":                owner.ID.String(),
		"email":              owner.Email,
		"jti":                userJTI,
		authctx.ClaimOrg:     org.ID.String(),
		authctx.ClaimOrgRole: pb.Role_Owner.String(),
	})

	orig := service.JwtParser.GetRevocation()
	rev := &fakeRevocation{}
	service.JwtParser.SetRevocation(rev)
	t.Cleanup(func() { service.JwtParser.SetRevocation(orig) })

	// a user signs out
	_, err := service.RevokeToken(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	assert.Equal(t, []string{userJTI}, rev.revoked)
	requireEvent(t, wantEvent{
		OrgID:       org.ID.UInt64(),
		Email:       owner.Email,
		Title:       "User signed out",
		Description: fmt.Sprintf("%s signed out and revoked token %s", owner.Email, userJTI),
	}, waitEvent(t, pb.EventType_UserSignedOut, owner.ID))

	// the token of an API key is revoked: the key is the subject
	keyID := testDb.NextID()
	keyEmail := keyID.String() + "+apikey@trustyca.com"
	keyJTI := testDb.NextID().String()
	ctx = tokenCtx(keyID.String(), org.ID.String(), map[string]any{
		"sub":                keyID.String(),
		"email":              keyEmail,
		"jti":                keyJTI,
		authctx.ClaimOrg:     org.ID.String(),
		authctx.ClaimOrgRole: pb.Role_APIKey.String(),
		authctx.ClaimProject: project.ID.String(),
	})
	_, err = service.RevokeToken(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	assert.Equal(t, []string{userJTI, keyJTI}, rev.revoked)
	requireEvent(t, wantEvent{
		OrgID:       org.ID.UInt64(),
		ProjectID:   project.ID.UInt64(),
		Email:       keyEmail,
		Title:       "Token revoked",
		Description: "API key token " + keyJTI + " revoked",
	}, waitEvent(t, pb.EventType_TokenRevoked, keyID))
}

func Test_AuthenticateAPIKey_Event(t *testing.T) {
	t.Parallel()
	service := testServer.Service(auth.ServiceName).(*auth.Service)
	ctx := t.Context()
	owner, org := newOwnerOrg(t)
	project := newProject(t, org.ID)

	// the key as orgs.CreateAPIKey stores it
	keyID := testDb.NextID()
	protectedID, err := dataprotection.ProtectObject(ctx, testDp, keyID.String())
	require.NoError(t, err)
	secret := certutil.RandomString(32)
	protectedSecret, err := dataprotection.ProtectObject(ctx, testDp, secret)
	require.NoError(t, err)
	key, err := testDb.RegisterAPIKey(ctx, &model.APIKey{
		ID:        keyID,
		OrgID:     org.ID,
		ProjectID: project.ID,
		Key:       fmt.Sprintf("sk_%s_%s", org.ID, protectedID),
		Secret:    protectedSecret,
		Label:     "ci",
		Scopes:    authctx.DefaultAPIKeyScopes,
		Status:    pb.ItemStatus_Active,
		ExpiresAt: xdb.Time(time.Now().Add(time.Hour)),
		Metadata: xdb.Metadata{
			"created_by": owner.Email,
		},
	})
	require.NoError(t, err)

	// the signature is HMAC-SHA256 of the method and timestamp under the secret
	timestamp := time.Now().UTC().Format(time.RFC3339)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(pb.Auth_AuthenticateAPIKey_FullMethodName))
	mac.Write([]byte(timestamp))
	signature := base64.URLEncoding.EncodeToString(mac.Sum(nil))

	w := httptest.NewRecorder()
	r, err := http.NewRequest(http.MethodPost, pb.Auth_AuthenticateAPIKey_FullMethodName, nil)
	require.NoError(t, err)
	r.Header.Set(header.Authorization, fmt.Sprintf("APIKey %s:%s", key.Key, signature))
	r.Header.Set(dateHeader, timestamp)
	service.AuthenticateAPIKeyHandler()(w, r, nil)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	keyEmail := keyID.String() + "+apikey@trustyca.com"
	requireEvent(t, wantEvent{
		OrgID:       org.ID.UInt64(),
		ProjectID:   project.ID.UInt64(),
		Email:       keyEmail,
		Title:       "API key signed in",
		Description: `API key "ci" signed in`,
	}, waitEvent(t, pb.EventType_APIKeyLogin, keyID))
}

// oauthServer is a GitLab stand-in that signs in the email sent as the
// authorization code: the code becomes the access token, and the access
// token the email of the user info
func oauthServer(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(header.ContentType, header.ApplicationJSON)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": r.FormValue("code"),
			"token_type":   "bearer",
			"expires_in":   3600,
		})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		email := strings.TrimPrefix(r.Header.Get(header.Authorization), "Bearer ")
		w.Header().Set(header.ContentType, header.ApplicationJSON)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":             email,
			"email":          email,
			"email_verified": true,
			"name":           "Events User",
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func Test_CallbackHandler_Events(t *testing.T) {
	// registers a provider and sets BaseURL on the shared service: not
	// parallel. GetUserInfo sends the user info request to BaseURL, which
	// earlier tests leave pointing at their own fixtures.
	service := testServer.Service(auth.ServiceName).(*auth.Service)
	ctx := t.Context()
	srv := oauthServer(t)
	baseURL, err := url.Parse(srv.URL)
	require.NoError(t, err)
	oldURL := service.BaseURL
	service.BaseURL = baseURL
	t.Cleanup(func() { service.BaseURL = oldURL })

	err = service.SetAuthProvider(ctx, &oauth2client.ClientConfig{
		ProviderID:   strings.ToLower(pb.IDP_Gitlab.String()),
		ClientID:     "1234",
		ClientSecret: "1234",
		Scopes:       []string{"email"},
		RedirectURL:  "http://localhost:38989",
		ResponseType: pb.OAuthResponseTypeCode,
		AuthURL:      srv.URL + "/authorize",
		TokenURL:     srv.URL + "/token",
		UserinfoURL:  srv.URL + "/userinfo",
	})
	require.NoError(t, err)

	// login signs in the email and returns the claims of the issued token
	// and the user ID
	login := func(t *testing.T, email string) (jwt.MapClaims, xdb.ID) {
		t.Helper()
		st, err := service.Protect(ctx, &auth.State{
			Provider:     pb.IDP_Gitlab,
			ClientID:     "1234",
			Scope:        "email",
			RedirectURL:  "http://localhost:38989",
			ResponseType: pb.OAuthResponseTypeToken,
			IssuedAt:     time.Now().Unix(),
		})
		require.NoError(t, err)

		params := url.Values{
			"code":  {email},
			"state": {st},
		}
		w := httptest.NewRecorder()
		r, err := http.NewRequest(http.MethodPost, pb.PathForAuthCallback, strings.NewReader(params.Encode()))
		require.NoError(t, err)
		r.Header.Add(header.ContentType, "application/x-www-form-urlencoded")
		service.CallbackHandler()(w, r, nil)
		require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())

		loc, err := url.Parse(w.Header().Get(header.Location))
		require.NoError(t, err)
		claims, err := service.JwtParser.ParseToken(ctx, urlutil.GetQueryString(loc, pb.OAuthResponseTypeToken), nil)
		require.NoError(t, err)
		userID, err := xdb.ParseID(claims.String("sub"))
		require.NoError(t, err)
		return claims, userID
	}

	t.Run("invited", func(t *testing.T) {
		owner, org := newOwnerOrg(t)
		project := newProject(t, org.ID)
		email := newEmail()
		deleteUserOnCleanup(t, email)
		for _, inv := range []*model.Invite{
			{OrgID: org.ID, InviterID: owner.ID, Email: email, Role: pb.Role_User},
			{OrgID: org.ID, ProjectID: project.ID, InviterID: owner.ID, Email: email, Role: pb.Role_Admin},
		} {
			_, err := testDb.CreateInvite(ctx, inv)
			require.NoError(t, err)
		}

		// the session starts in the org of the invites
		claims, userID := login(t, email)
		assert.Equal(t, org.ID.String(), claims.String(authctx.ClaimOrg))

		requireEvent(t, wantEvent{
			Email:       email,
			Title:       "User signed up",
			Description: email + " signed up with Gitlab",
		}, waitEvent(t, pb.EventType_UserSignup, userID))
		requireEvent(t, wantEvent{
			OrgID:       org.ID.UInt64(),
			Email:       email,
			Title:       "Member accepted invitation",
			Description: email + " accepted the invitation as User",
		}, waitEvent(t, pb.EventType_OrgMemberAccepted, userID))
		requireEvent(t, wantEvent{
			OrgID:       org.ID.UInt64(),
			ProjectID:   project.ID.UInt64(),
			Email:       email,
			Title:       "Member accepted invitation",
			Description: email + " accepted the invitation as Admin",
		}, waitEvent(t, pb.EventType_ProjectMemberAccepted, userID))
		requireEvent(t, wantEvent{
			OrgID:       org.ID.UInt64(),
			Email:       email,
			Title:       "User signed in",
			Description: email + " signed in with Gitlab as User",
		}, waitEvent(t, pb.EventType_UserSignedIn, userID))
	})

	t.Run("default_org", func(t *testing.T) {
		email := newEmail()
		deleteUserOnCleanup(t, email)

		// a user without grants gets the default org and project
		claims, userID := login(t, email)
		orgID, err := xdb.ParseID(claims.String(authctx.ClaimOrg))
		require.NoError(t, err)
		deleteOrgOnCleanup(t, orgID)
		org, err := testDb.GetOrg(ctx, orgID.UInt64())
		require.NoError(t, err)
		projects, err := testDb.ListProjects(ctx, &query.ListProjectsRequest{OrgID: orgID.UInt64(), Limit: 10})
		require.NoError(t, err)
		require.Len(t, projects.Rows, 1)
		project := projects.Rows[0]

		requireEvent(t, wantEvent{
			Email:       email,
			Title:       "User signed up",
			Description: email + " signed up with Gitlab",
		}, waitEvent(t, pb.EventType_UserSignup, userID))
		requireEvent(t, wantEvent{
			OrgID:       orgID.UInt64(),
			Email:       email,
			Title:       "Org created",
			Description: fmt.Sprintf("default org %q created for %s", org.Name, email),
		}, waitEvent(t, pb.EventType_OrgCreated, orgID))
		requireEvent(t, wantEvent{
			OrgID:       orgID.UInt64(),
			ProjectID:   project.ID.UInt64(),
			Email:       email,
			Title:       "Project created",
			Description: fmt.Sprintf("default project %q created", project.Name),
		}, waitEvent(t, pb.EventType_ProjectCreated, project.ID))
		requireEvent(t, wantEvent{
			OrgID:       orgID.UInt64(),
			Email:       email,
			Title:       "User signed in",
			Description: email + " signed in with Gitlab as Owner",
		}, waitEvent(t, pb.EventType_UserSignedIn, userID))

		// signing in again is not a sign-up and keeps the org
		claims, again := login(t, email)
		assert.Equal(t, userID.UInt64(), again.UInt64())
		assert.Equal(t, orgID.String(), claims.String(authctx.ClaimOrg))
		waitEvents(t, &query.ListEventsRequest{Type: pb.EventType_UserSignedIn, ReferenceID: userID.UInt64()}, 2)
		waitEvents(t, &query.ListEventsRequest{Type: pb.EventType_UserSignup, ReferenceID: userID.UInt64()}, 1)
	})
}
