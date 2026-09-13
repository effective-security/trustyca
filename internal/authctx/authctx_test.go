package authctx_test

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/xhttp/identity"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/authctx"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/tests/testutils"
	"github.com/effective-security/xdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// identityFor returns a user identity with the selected org in the token
func identityFor(userID, orgID, orgRole string) identity.Identity {
	c := map[string]any{
		"sub":   userID,
		"email": userID + "@example.com",
		"name":  "User " + userID,
	}
	if orgID != "" {
		c[authctx.ClaimOrg] = orgID
		c[authctx.ClaimOrgRole] = orgRole
		c[authctx.ClaimOrgRoleSource] = "direct"
	}
	return identity.NewIdentity("user", userID, orgID, c, "accessToken", "Bearer", identity.MethodJWT)
}

// apiKeyIdentity returns an API key token identity with the scopes and an
// optional project restriction
func apiKeyIdentity(keyID, orgID, projectID string, scopes ...string) identity.Identity {
	c := map[string]any{
		"sub":                keyID,
		"email":              keyID + "+apikey@example.com",
		authctx.ClaimOrg:     orgID,
		authctx.ClaimOrgRole: pb.Role_APIKey.String(),
		authctx.ClaimScope:   scopes,
	}
	if projectID != "" {
		c[authctx.ClaimProject] = projectID
	}
	return identity.NewIdentity("user", keyID, orgID, c, "accessToken", "Bearer", identity.MethodJWT)
}

func requestCtx(uid identity.Identity) context.Context {
	_, r, _ := testutils.CreateRequest(http.MethodGet, "/test", nil, uid)
	return r.Context()
}

func Test_TrustyCtx(t *testing.T) {
	t.Parallel()
	uid := identityFor("12345", "23456", pb.Role_Admin.String())
	_, r, _ := testutils.CreateRequest(http.MethodGet, "/test", nil, uid)

	authCtx := authctx.FromRequest(r)
	assert.Equal(t, uint64(12345), authCtx.UserID().UInt64())
	assert.Equal(t, uint64(23456), authCtx.OrgID().UInt64())
	assert.Equal(t, pb.Role_Admin, authCtx.OrgRole())
	assert.False(t, authCtx.IsAPIKey())
	assert.Empty(t, authCtx.Scopes())
	assert.Equal(t, "user", authCtx.AppRole())
	assert.Equal(t, "User 12345", authCtx.Name())
	assert.Equal(t, "12345@example.com", authCtx.Email())
	assert.Equal(t, identity.MethodJWT, authCtx.AuthMethod())

	h := func(w http.ResponseWriter, r *http.Request) {
		authCtx := authctx.FromRequest(r)
		assert.Equal(t, uint64(12345), authCtx.UserID().UInt64())
		assert.Equal(t, uint64(23456), authCtx.OrgID().UInt64())
		w.WriteHeader(http.StatusOK)
	}
	rw := httptest.NewRecorder()
	authctx.Handler(http.HandlerFunc(h)).ServeHTTP(rw, r)
	assert.Equal(t, http.StatusOK, rw.Code)
}

func Test_TrustyCtx_APIKey(t *testing.T) {
	t.Parallel()
	uid := apiKeyIdentity("777", "100", "201", "certs:read", "ca:*")
	_, r, _ := testutils.CreateRequest(http.MethodGet, "/test", nil, uid)

	authCtx := authctx.FromRequest(r)
	assert.True(t, authCtx.IsAPIKey())
	assert.Equal(t, pb.Role_APIKey, authCtx.OrgRole())
	assert.Equal(t, uint64(100), authCtx.OrgID().UInt64())
	assert.Equal(t, uint64(201), authCtx.ProjectID().UInt64())
	assert.Equal(t, []string{"certs:read", "ca:*"}, authCtx.Scopes())
}

func Test_FromContext_Empty(t *testing.T) {
	t.Parallel()
	ctx := authctx.FromContext(context.Background())
	assert.Equal(t, uint64(0), ctx.UserID().UInt64())
	assert.Equal(t, uint64(0), ctx.OrgID().UInt64())
	assert.Equal(t, pb.Role_None, ctx.OrgRole())
	assert.Empty(t, ctx.AppRole())
}

func Test_NewTrustyCtx_Guest(t *testing.T) {
	t.Parallel()
	uid := identity.NewIdentity("guest", "", "", nil, "", "", identity.MethodNone)
	_, r, _ := testutils.CreateRequest(http.MethodGet, "/test", nil, uid)
	authCtx := authctx.FromRequest(r)
	assert.Equal(t, "guest", authCtx.AppRole())
	assert.Equal(t, uint64(0), authCtx.UserID().UInt64())
	assert.Equal(t, uint64(0), authCtx.OrgID().UInt64())
}

// mockGrants provides memberships and projects to the authorizer
type mockGrants struct {
	byUser   map[uint64]model.MembershipInfoSlice
	projects map[uint64]*model.Project
	err      error
	// calls counts ListMemberships calls
	calls int
	// projectCalls counts GetProject calls
	projectCalls int
}

func (m *mockGrants) ListMemberships(_ context.Context, req *query.ListMembershipsRequest) (model.MembershipInfoSlice, error) {
	m.calls++
	if m.err != nil {
		return nil, m.err
	}
	return m.byUser[req.UserID], nil
}

func (m *mockGrants) GetProject(_ context.Context, id uint64) (*model.Project, error) {
	m.projectCalls++
	if m.err != nil {
		return nil, m.err
	}
	if p, ok := m.projects[id]; ok {
		return p, nil
	}
	return nil, sql.ErrNoRows
}

var (
	orgID      = xdb.NewID(100)
	otherOrgID = xdb.NewID(101)
	ownerID    = xdb.NewID(304)
	adminID    = xdb.NewID(302)
	userID     = xdb.NewID(300)
	projOnlyID = xdb.NewID(301)
	viewerID   = xdb.NewID(303)
	securityID = xdb.NewID(306)
	strangerID = xdb.NewID(999)
)

// specGrants implements the spec example: org 100 with projects 201, 202,
// 203 (inactive); org 101 has project 301.
func specGrants() *mockGrants {
	return &mockGrants{
		byUser: map[uint64]model.MembershipInfoSlice{
			ownerID.UInt64(): {{ID: xdb.NewID(1), OrgID: orgID, UserID: ownerID, Role: pb.Role_Owner}},
			adminID.UInt64(): {
				{ID: xdb.NewID(2), OrgID: orgID, UserID: adminID, Role: pb.Role_Admin},
				{ID: xdb.NewID(3), OrgID: orgID, ProjectID: xdb.NewID(201), UserID: adminID, Role: pb.Role_Viewer},
			},
			userID.UInt64(): {
				{ID: xdb.NewID(4), OrgID: orgID, UserID: userID, Role: pb.Role_User},
				{ID: xdb.NewID(5), OrgID: orgID, ProjectID: xdb.NewID(201), UserID: userID, Role: pb.Role_Admin},
			},
			projOnlyID.UInt64(): {
				{ID: xdb.NewID(6), OrgID: orgID, ProjectID: xdb.NewID(201), UserID: projOnlyID, Role: pb.Role_Admin},
			},
			viewerID.UInt64():   {{ID: xdb.NewID(7), OrgID: orgID, UserID: viewerID, Role: pb.Role_Viewer}},
			securityID.UInt64(): {{ID: xdb.NewID(8), OrgID: orgID, UserID: securityID, Role: pb.Role_Security}},
		},
		projects: map[uint64]*model.Project{
			201: {ID: xdb.NewID(201), OrgID: orgID, Alias: "p1", Name: "P1", Status: pb.ItemStatus_Active},
			202: {ID: xdb.NewID(202), OrgID: orgID, Alias: "p2", Name: "P2", Status: pb.ItemStatus_Active},
			203: {ID: xdb.NewID(203), OrgID: orgID, Alias: "p3", Name: "P3", Status: pb.ItemStatus_Inactive},
			301: {ID: xdb.NewID(301), OrgID: otherOrgID, Alias: "foreign", Name: "Foreign", Status: pb.ItemStatus_Active},
		},
	}
}

func Test_Authorizer(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	provider := specGrants()
	a := authctx.NewAuthorizer(provider)

	t.Run("grants_and_cache", func(t *testing.T) {
		g, err := a.Grants(ctx, orgID, userID)
		require.NoError(t, err)
		assert.Equal(t, pb.Role_User, g.OrgRole)
		assert.Equal(t, pb.Role_Admin, g.ProjectRoles[201])
		calls := provider.calls

		g, err = a.Grants(ctx, orgID, userID)
		require.NoError(t, err)
		assert.True(t, g.IsMember())
		assert.Equal(t, calls, provider.calls, "served from cache")

		a.InvalidateUser(ctx, userID.String())
		_, err = a.Grants(ctx, orgID, userID)
		require.NoError(t, err)
		assert.Equal(t, calls+1, provider.calls)

		g, err = a.Grants(ctx, orgID, strangerID)
		require.NoError(t, err)
		assert.False(t, g.IsMember())

		_, err = a.Grants(ctx, xdb.ID{}, userID)
		assert.ErrorIs(t, err, authctx.ErrOrgNotSelected)
	})

	t.Run("project", func(t *testing.T) {
		p, err := a.Project(ctx, orgID, xdb.NewID(201))
		require.NoError(t, err)
		assert.Equal(t, "p1", p.Alias)
		calls := provider.projectCalls
		_, err = a.Project(ctx, orgID, xdb.NewID(201))
		require.NoError(t, err)
		assert.Equal(t, calls, provider.projectCalls, "served from cache")
		a.InvalidateProject(ctx, "201")
		_, err = a.Project(ctx, orgID, xdb.NewID(201))
		require.NoError(t, err)
		assert.Equal(t, calls+1, provider.projectCalls)

		// inactive, foreign and unknown projects are all denied the same way
		_, err = a.Project(ctx, orgID, xdb.NewID(203))
		assert.ErrorIs(t, err, authctx.ErrAccessDenied)
		_, err = a.Project(ctx, orgID, xdb.NewID(301))
		assert.ErrorIs(t, err, authctx.ErrAccessDenied)
		_, err = a.Project(ctx, orgID, xdb.NewID(999))
		assert.ErrorIs(t, err, authctx.ErrAccessDenied)
		_, err = a.Project(ctx, xdb.ID{}, xdb.NewID(201))
		assert.ErrorIs(t, err, authctx.ErrOrgNotSelected)
	})

	t.Run("check_role_org_scope", func(t *testing.T) {
		role, _, err := a.CheckRole(ctx, orgID, xdb.ID{}, ownerID, "Owner")
		require.NoError(t, err)
		assert.Equal(t, pb.Role_Owner, role)
		_, _, err = a.CheckRole(ctx, orgID, xdb.ID{}, adminID, "Owner")
		assert.ErrorIs(t, err, authctx.ErrInsufficientRole)
		role, _, err = a.CheckRole(ctx, orgID, xdb.ID{}, adminID, "Owner", "Admin")
		require.NoError(t, err, "any of the allowed roles")
		assert.Equal(t, pb.Role_Admin, role)
		// minimum roles: Security assumes User, Viewer does not
		_, _, err = a.CheckRole(ctx, orgID, xdb.ID{}, securityID, "User", "APIKey")
		require.NoError(t, err)
		_, _, err = a.CheckRole(ctx, orgID, xdb.ID{}, viewerID, "User", "APIKey")
		assert.ErrorIs(t, err, authctx.ErrInsufficientRole)
		// derived Viewer has the minimal org context only
		role, _, err = a.CheckRole(ctx, orgID, xdb.ID{}, projOnlyID, "Viewer")
		require.NoError(t, err)
		assert.Equal(t, pb.Role_Viewer, role)
		_, _, err = a.CheckRole(ctx, orgID, xdb.ID{}, projOnlyID, "User")
		assert.ErrorIs(t, err, authctx.ErrInsufficientRole)
		// project Admin never becomes org Admin
		_, _, err = a.CheckRole(ctx, orgID, xdb.ID{}, userID, "Admin")
		assert.ErrorIs(t, err, authctx.ErrInsufficientRole)
		// stranger
		_, _, err = a.CheckRole(ctx, orgID, xdb.ID{}, strangerID, "Viewer")
		assert.ErrorIs(t, err, authctx.ErrInsufficientRole)
		_, _, err = a.CheckRole(ctx, orgID, xdb.ID{}, strangerID)
		assert.ErrorIs(t, err, authctx.ErrInsufficientRole, "membership is required even without allowed roles")
	})

	t.Run("check_role_project_scope", func(t *testing.T) {
		// 300: User org-wide + Admin in 201
		role, _, err := a.CheckRole(ctx, orgID, xdb.NewID(201), userID, "Admin")
		require.NoError(t, err)
		assert.Equal(t, pb.Role_Admin, role)
		_, _, err = a.CheckRole(ctx, orgID, xdb.NewID(202), userID, "Admin")
		assert.ErrorIs(t, err, authctx.ErrInsufficientRole)
		role, _, err = a.CheckRole(ctx, orgID, xdb.NewID(202), userID, "User")
		require.NoError(t, err, "inherited from org User")
		assert.Equal(t, pb.Role_User, role)
		// 301: project only
		_, _, err = a.CheckRole(ctx, orgID, xdb.NewID(201), projOnlyID, "Admin")
		require.NoError(t, err)
		_, _, err = a.CheckRole(ctx, orgID, xdb.NewID(202), projOnlyID, "Viewer")
		assert.ErrorIs(t, err, authctx.ErrInsufficientRole)
		// 302: org Admin keeps Admin despite project Viewer
		role, _, err = a.CheckRole(ctx, orgID, xdb.NewID(201), adminID, "Admin")
		require.NoError(t, err)
		assert.Equal(t, pb.Role_Admin, role)
		// 303: org Viewer reads every project, including one without grants
		_, _, err = a.CheckRole(ctx, orgID, xdb.NewID(202), viewerID, "Viewer")
		require.NoError(t, err)
		_, _, err = a.CheckRole(ctx, orgID, xdb.NewID(202), viewerID, "User")
		assert.ErrorIs(t, err, authctx.ErrInsufficientRole)
		// project of another org, inactive project
		_, _, err = a.CheckRole(ctx, orgID, xdb.NewID(301), ownerID, "Viewer")
		assert.ErrorIs(t, err, authctx.ErrAccessDenied)
		_, _, err = a.CheckRole(ctx, orgID, xdb.NewID(203), ownerID, "Viewer")
		assert.ErrorIs(t, err, authctx.ErrAccessDenied)
	})

	t.Run("provider_error", func(t *testing.T) {
		failing := authctx.NewAuthorizer(&mockGrants{err: errors.New("db down")})
		_, err := failing.Grants(ctx, orgID, adminID)
		assert.ErrorContains(t, err, "unable to get user memberships")
		_, err = failing.Project(ctx, orgID, xdb.NewID(201))
		assert.ErrorContains(t, err, "unable to get project")
		_, _, err = failing.CheckRole(ctx, orgID, xdb.ID{}, adminID, "Viewer")
		assert.ErrorContains(t, err, "unable to get user memberships")
	})
}

func Test_CheckAccess(t *testing.T) {
	t.Parallel()
	a := authctx.NewAuthorizer(specGrants())
	org := orgID.String()

	t.Run("no_allowed_roles_requires_nothing", func(t *testing.T) {
		ctx := requestCtx(identityFor(strangerID.String(), "", ""))
		assert.NoError(t, authctx.CheckAccess(ctx, a, &emptypb.Empty{}, "/pb.Notfound"))
		assert.NoError(t, authctx.CheckAccess(ctx, a, &pb.RegisterOrgRequest{Name: "x"}, "/pb.Orgs/RegisterOrg"))
		assert.NoError(t, authctx.CheckAccess(ctx, a, &emptypb.Empty{}, "/pb.Orgs/GetUserOrgs"))
		// identity and session methods are gated by the server config
		assert.NoError(t, authctx.CheckAccess(ctx, a, &pb.SelectOrgRequest{OrgID: org}, "/pb.Auth/SelectOrg"))
		assert.NoError(t, authctx.CheckAccess(ctx, a, &emptypb.Empty{}, "/pb.Auth/RevokeToken"))
	})

	t.Run("guest_and_unauthenticated", func(t *testing.T) {
		uid := identity.NewIdentity("guest", "", "", nil, "", "", identity.MethodNone)
		err := authctx.CheckAccess(requestCtx(uid), a, &pb.GetMembersRequest{}, "/pb.Orgs/GetMembers")
		assert.EqualError(t, err, "unauthorized: access denied")

		uid = identity.NewIdentity("", "1", "", map[string]any{"sub": "1"}, "", "", identity.MethodJWT)
		err = authctx.CheckAccess(requestCtx(uid), a, &pb.GetMembersRequest{}, "/pb.Orgs/GetMembers")
		assert.EqualError(t, err, "unauthorized: access denied")
	})

	t.Run("org_not_selected", func(t *testing.T) {
		ctx := requestCtx(identityFor(ownerID.String(), "", ""))
		err := authctx.CheckAccess(ctx, a, &emptypb.Empty{}, "/pb.Orgs/GetOrg")
		assert.EqualError(t, err, "unauthorized: org not selected, action: /pb.Orgs/GetOrg")
	})

	t.Run("org_scope_roles", func(t *testing.T) {
		owner := requestCtx(identityFor(ownerID.String(), org, "Owner"))
		assert.NoError(t, authctx.CheckAccess(owner, a, &emptypb.Empty{}, "/pb.Orgs/DeleteOrg"))
		assert.NoError(t, authctx.CheckAccess(owner, a, &pb.AddMemberRequest{Email: "a@b.c", Role: pb.Role_User}, "/pb.Orgs/AddMember"))

		admin := requestCtx(identityFor(adminID.String(), org, "Admin"))
		assert.NoError(t, authctx.CheckAccess(admin, a, &pb.GetMembersRequest{}, "/pb.Orgs/GetMembers"))
		assert.NoError(t, authctx.CheckAccess(admin, a, &pb.CreateAPIKeyRequest{Label: "k"}, "/pb.Orgs/CreateAPIKey"))
		err := authctx.CheckAccess(admin, a, &emptypb.Empty{}, "/pb.Orgs/DeleteOrg")
		assert.EqualError(t, err, "unauthorized: insufficient role, action: /pb.Orgs/DeleteOrg")

		// Security assumes Support for GetMembers, but not Admin
		security := requestCtx(identityFor(securityID.String(), org, "Security"))
		assert.NoError(t, authctx.CheckAccess(security, a, &pb.GetMembersRequest{}, "/pb.Orgs/GetMembers"))
		err = authctx.CheckAccess(security, a, &pb.RegisterProjectRequest{Name: "x"}, "/pb.Orgs/RegisterProject")
		assert.EqualError(t, err, "unauthorized: insufficient role, action: /pb.Orgs/RegisterProject")

		user := requestCtx(identityFor(userID.String(), org, "User"))
		assert.NoError(t, authctx.CheckAccess(user, a, &emptypb.Empty{}, "/pb.Orgs/GetOrg"))
		err = authctx.CheckAccess(user, a, &pb.AddMemberRequest{Email: "a@b.c", Role: pb.Role_User}, "/pb.Orgs/AddMember")
		assert.EqualError(t, err, "unauthorized: insufficient role, action: /pb.Orgs/AddMember")
		err = authctx.CheckAccess(user, a, &pb.GetMembersRequest{}, "/pb.Orgs/GetMembers")
		assert.EqualError(t, err, "unauthorized: insufficient role, action: /pb.Orgs/GetMembers")

		// derived Viewer: minimal org context only
		derived := requestCtx(identityFor(projOnlyID.String(), org, "Viewer"))
		assert.NoError(t, authctx.CheckAccess(derived, a, &emptypb.Empty{}, "/pb.Orgs/GetOrg"))
		assert.NoError(t, authctx.CheckAccess(derived, a, &pb.ListProjectsRequest{}, "/pb.Orgs/ListProjects"))
		err = authctx.CheckAccess(derived, a, &pb.GetMembersRequest{}, "/pb.Orgs/GetMembers")
		assert.EqualError(t, err, "unauthorized: insufficient role, action: /pb.Orgs/GetMembers")

		stranger := requestCtx(identityFor(strangerID.String(), org, ""))
		err = authctx.CheckAccess(stranger, a, &emptypb.Empty{}, "/pb.Orgs/GetOrg")
		assert.EqualError(t, err, "unauthorized: insufficient role, action: /pb.Orgs/GetOrg")
	})

	t.Run("project_scope_roles", func(t *testing.T) {
		user := requestCtx(identityFor(userID.String(), org, "User"))
		// project Admin in 201 manages grants there
		assert.NoError(t, authctx.CheckAccess(user, a, &pb.AddMemberRequest{ProjectID: "201", Email: "a@b.c", Role: pb.Role_User}, "/pb.Orgs/AddMember"))
		assert.NoError(t, authctx.CheckAccess(user, a, &pb.GetMembersRequest{ProjectID: "201"}, "/pb.Orgs/GetMembers"))
		// but not in 202, where only the org User grant applies
		err := authctx.CheckAccess(user, a, &pb.AddMemberRequest{ProjectID: "202", Email: "a@b.c", Role: pb.Role_User}, "/pb.Orgs/AddMember")
		assert.EqualError(t, err, "unauthorized: insufficient role, action: /pb.Orgs/AddMember")
		assert.NoError(t, authctx.CheckAccess(user, a, &pb.GetProjectRequest{ProjectID: "202"}, "/pb.Orgs/GetProject"))

		// project-only member
		derived := requestCtx(identityFor(projOnlyID.String(), org, "Viewer"))
		assert.NoError(t, authctx.CheckAccess(derived, a, &pb.UpdateProjectRequest{ProjectID: "201", Name: "n"}, "/pb.Orgs/UpdateProject"))
		err = authctx.CheckAccess(derived, a, &pb.GetProjectRequest{ProjectID: "202"}, "/pb.Orgs/GetProject")
		assert.EqualError(t, err, "unauthorized: insufficient role, action: /pb.Orgs/GetProject")

		// cross-org and inactive projects are rejected even for the Owner
		owner := requestCtx(identityFor(ownerID.String(), org, "Owner"))
		err = authctx.CheckAccess(owner, a, &pb.GetProjectRequest{ProjectID: "301"}, "/pb.Orgs/GetProject")
		assert.EqualError(t, err, "unauthorized: access denied, action: /pb.Orgs/GetProject")
		err = authctx.CheckAccess(owner, a, &pb.GetProjectRequest{ProjectID: "203"}, "/pb.Orgs/GetProject")
		assert.EqualError(t, err, "unauthorized: access denied, action: /pb.Orgs/GetProject")
		err = authctx.CheckAccess(owner, a, &pb.GetProjectRequest{ProjectID: "not-a-number"}, "/pb.Orgs/GetProject")
		assert.EqualError(t, err, "bad_request: invalid project ID")
	})

	t.Run("explicit_org_must_match_token", func(t *testing.T) {
		owner := requestCtx(identityFor(ownerID.String(), org, "Owner"))
		assert.NoError(t, authctx.CheckAccess(owner, a, &orgReq{orgID: org}, "/pb.Orgs/GetOrg"))
		assert.NoError(t, authctx.CheckAccess(owner, a, &orgReq{}, "/pb.Orgs/GetOrg"))
		err := authctx.CheckAccess(owner, a, &orgReq{orgID: otherOrgID.String()}, "/pb.Orgs/GetOrg")
		assert.EqualError(t, err, "unauthorized: org mismatch, action: /pb.Orgs/GetOrg")
	})

	t.Run("api_key", func(t *testing.T) {
		// org scoped key with read scopes
		key := requestCtx(apiKeyIdentity("777", org, "", "org:read", "project:read"))
		assert.NoError(t, authctx.CheckAccess(key, a, &emptypb.Empty{}, "/pb.Orgs/GetOrg"))
		assert.NoError(t, authctx.CheckAccess(key, a, &pb.GetProjectRequest{ProjectID: "201"}, "/pb.Orgs/GetProject"))
		// the method does not allow API keys at all
		err := authctx.CheckAccess(key, a, &pb.CreateAPIKeyRequest{Label: "k"}, "/pb.Orgs/CreateAPIKey")
		assert.EqualError(t, err, "unauthorized: API key not allowed, action: /pb.Orgs/CreateAPIKey")
		err = authctx.CheckAccess(key, a, &pb.GetMembersRequest{}, "/pb.Orgs/GetMembers")
		assert.EqualError(t, err, "unauthorized: API key not allowed, action: /pb.Orgs/GetMembers")
		// the key lacks the method scope
		err = authctx.CheckAccess(key, a, &pb.SignCertificateRequest{OrgID: org}, "/pb.CA/SignCertificate")
		assert.EqualError(t, err, "unauthorized: insufficient scope, action: /pb.CA/SignCertificate")
		// inactive or foreign project
		err = authctx.CheckAccess(key, a, &pb.GetProjectRequest{ProjectID: "203"}, "/pb.Orgs/GetProject")
		assert.EqualError(t, err, "unauthorized: access denied, action: /pb.Orgs/GetProject")

		// wildcard scopes
		wide := requestCtx(apiKeyIdentity("778", org, "", "*"))
		assert.NoError(t, authctx.CheckAccess(wide, a, &pb.SignCertificateRequest{OrgID: org}, "/pb.CA/SignCertificate"))
		certs := requestCtx(apiKeyIdentity("779", org, "", "certs:*"))
		assert.NoError(t, authctx.CheckAccess(certs, a, &pb.SignCertificateRequest{OrgID: org}, "/pb.CA/SignCertificate"))
		err = authctx.CheckAccess(certs, a, &pb.ListIssuersRequest{OrgID: org}, "/pb.CA/ListIssuers")
		assert.EqualError(t, err, "unauthorized: insufficient scope, action: /pb.CA/ListIssuers")

		// project scoped key acts in its project only
		pkey := requestCtx(apiKeyIdentity("780", org, "201", "project:read", "certs:issue"))
		assert.NoError(t, authctx.CheckAccess(pkey, a, &pb.GetProjectRequest{ProjectID: "201"}, "/pb.Orgs/GetProject"))
		assert.NoError(t, authctx.CheckAccess(pkey, a, &pb.SignCertificateRequest{OrgID: org}, "/pb.CA/SignCertificate"), "no ProjectID defaults to the key project")
		err = authctx.CheckAccess(pkey, a, &pb.GetProjectRequest{ProjectID: "202"}, "/pb.Orgs/GetProject")
		assert.EqualError(t, err, "unauthorized: project mismatch, action: /pb.Orgs/GetProject")
	})

	t.Run("scoped_user_token", func(t *testing.T) {
		c := map[string]any{
			"sub":                ownerID.String(),
			authctx.ClaimOrg:     org,
			authctx.ClaimOrgRole: "Owner",
			authctx.ClaimScope:   []string{"org:read"},
		}
		uid := identity.NewIdentity("user", ownerID.String(), org, c, "tok", "Bearer", identity.MethodJWT)
		ctx := requestCtx(uid)
		assert.NoError(t, authctx.CheckAccess(ctx, a, &emptypb.Empty{}, "/pb.Orgs/GetOrg"))
		err := authctx.CheckAccess(ctx, a, &pb.GetProjectRequest{ProjectID: "201"}, "/pb.Orgs/GetProject")
		assert.EqualError(t, err, "unauthorized: insufficient scope, action: /pb.Orgs/GetProject")
		// methods without scopes are limited by roles only
		assert.NoError(t, authctx.CheckAccess(ctx, a, &pb.GetMembersRequest{}, "/pb.Orgs/GetMembers"))
	})

	t.Run("service_roles", func(t *testing.T) {
		uid := identity.NewIdentity("trustyca-ra", "spiffe://trustyca/ra", "", nil, "", "", identity.MethodJWT)
		ctx := requestCtx(uid)
		assert.NoError(t, authctx.CheckAccess(ctx, a, &pb.SignCertificateRequest{OrgID: org}, "/pb.CA/SignCertificate"))
		assert.NoError(t, authctx.CheckAccess(ctx, a, &emptypb.Empty{}, "/pb.Status/Version"))

		admin := requestCtx(identity.NewIdentity("trustyca-admin", "1", "", nil, "", "", identity.MethodJWT))
		assert.NoError(t, authctx.CheckAccess(admin, a, &emptypb.Empty{}, "/privpb.Admin/ListOrgs"))

		viewer := requestCtx(identity.NewIdentity("trustyca-viewer", "1", "", nil, "", "", identity.MethodJWT))
		assert.NoError(t, authctx.CheckAccess(viewer, a, &emptypb.Empty{}, "/privpb.Admin/ListOrgs"))
		err := authctx.CheckAccess(viewer, a, &emptypb.Empty{}, "/privpb.Admin/DeleteOrg")
		assert.EqualError(t, err, "unauthorized: access denied")

		user := requestCtx(identityFor(ownerID.String(), org, "Owner"))
		err = authctx.CheckAccess(user, a, &emptypb.Empty{}, "/privpb.Admin/ListOrgs")
		assert.EqualError(t, err, "unauthorized: access denied")
		assert.NoError(t, authctx.CheckAccess(user, a, &emptypb.Empty{}, "/pb.Status/Version"))
	})
}

func Test_GetAllowedMethods(t *testing.T) {
	t.Parallel()
	a := authctx.NewAuthorizer(specGrants())
	org := orgID.String()

	find := func(res *pb.ServiceAccessInfo, service, method string) bool {
		for _, si := range res.Allowed {
			if si.Service != service {
				continue
			}
			for _, m := range si.Methods {
				if m.Key == method {
					return true
				}
			}
		}
		return false
	}

	res, err := authctx.GetAllowedMethods(requestCtx(identityFor(ownerID.String(), org, "Owner")), a)
	require.NoError(t, err)
	assert.True(t, find(res, "Orgs", "DeleteOrg"))
	assert.True(t, find(res, "Orgs", "RegisterOrg"), "methods without roles are listed")
	assert.True(t, find(res, "Auth", "SelectOrg"))
	assert.False(t, find(res, "Admin", "ListOrgs"), "admin service is for service roles")

	res, err = authctx.GetAllowedMethods(requestCtx(identityFor(viewerID.String(), org, "Viewer")), a)
	require.NoError(t, err)
	assert.True(t, find(res, "Orgs", "GetOrg"))
	assert.False(t, find(res, "Orgs", "DeleteOrg"))
	assert.False(t, find(res, "Orgs", "GetMembers"))

	// project-only member at org scope: minimal context
	res, err = authctx.GetAllowedMethods(requestCtx(identityFor(projOnlyID.String(), org, "Viewer")), a)
	require.NoError(t, err)
	assert.True(t, find(res, "Orgs", "ListProjects"))
	assert.False(t, find(res, "Orgs", "UpdateProject"), "project roles are judged per request")

	// API key: role and scopes
	res, err = authctx.GetAllowedMethods(requestCtx(apiKeyIdentity("777", org, "", "org:read")), a)
	require.NoError(t, err)
	assert.True(t, find(res, "Orgs", "GetOrg"))
	assert.False(t, find(res, "Orgs", "GetProject"), "project:read scope missing")
	assert.False(t, find(res, "Orgs", "CreateAPIKey"))

	// service role sees the admin service
	res, err = authctx.GetAllowedMethods(requestCtx(identity.NewIdentity("trustyca-admin", "1", "", nil, "", "", identity.MethodJWT)), a)
	require.NoError(t, err)
	assert.True(t, find(res, "Admin", "ListOrgs"))

	// no org selected: identity methods only
	res, err = authctx.GetAllowedMethods(requestCtx(identityFor(ownerID.String(), "", "")), a)
	require.NoError(t, err)
	assert.True(t, find(res, "Auth", "SelectOrg"))
	assert.False(t, find(res, "Orgs", "GetOrg"))
}

func Test_GetCallerScope(t *testing.T) {
	t.Parallel()
	a := authctx.NewAuthorizer(specGrants())
	org := orgID.String()

	find := func(res *pb.CallerScope, method string) *pb.MethodAccess {
		for _, m := range res.Methods {
			if m.Method == method {
				return m
			}
		}
		return nil
	}

	// 300: org User with an Admin grant in project 201
	res, err := authctx.GetCallerScope(requestCtx(identityFor(userID.String(), org, "User")), a)
	require.NoError(t, err)
	assert.Equal(t, org, res.OrgID)
	assert.Empty(t, res.ProjectID)
	assert.Equal(t, pb.Role_User, res.Role)
	assert.Equal(t, pb.RoleSource_Direct, res.RoleSource)
	assert.Equal(t, map[string]string{"201": "Admin"}, res.ProjectRoles)
	assert.False(t, res.IsAPIKey)
	assert.Empty(t, res.Scopes)
	m := find(res, "/pb.Orgs/CreateAPIKey")
	require.NotNil(t, m)
	assert.Equal(t, []string{"Admin"}, m.AllowedRoles)
	assert.Empty(t, m.Scopes)
	assert.False(t, m.Allowed, "project Admin is not org Admin")
	m = find(res, "/pb.Orgs/GetProject")
	require.NotNil(t, m)
	assert.Equal(t, []string{"Viewer", "APIKey"}, m.AllowedRoles)
	assert.Equal(t, []string{"project:read"}, m.Scopes)
	assert.True(t, m.Allowed)
	assert.True(t, find(res, "/pb.Auth/SelectOrg").Allowed)

	// project-only member: derived Viewer
	res, err = authctx.GetCallerScope(requestCtx(identityFor(projOnlyID.String(), org, "Viewer")), a)
	require.NoError(t, err)
	assert.Equal(t, pb.Role_Viewer, res.Role)
	assert.Equal(t, pb.RoleSource_Project, res.RoleSource)
	assert.Equal(t, map[string]string{"201": "Admin"}, res.ProjectRoles)

	// API key
	res, err = authctx.GetCallerScope(requestCtx(apiKeyIdentity("780", org, "201", "certs:issue")), a)
	require.NoError(t, err)
	assert.True(t, res.IsAPIKey)
	assert.Equal(t, pb.Role_APIKey, res.Role)
	assert.Equal(t, "201", res.ProjectID)
	assert.Equal(t, []string{"certs:issue"}, res.Scopes)
	assert.Empty(t, res.ProjectRoles)
	assert.True(t, find(res, "/pb.CA/SignCertificate").Allowed)
	assert.False(t, find(res, "/pb.Orgs/GetOrg").Allowed, "org:read scope missing")
	assert.False(t, find(res, "/pb.Orgs/CreateAPIKey").Allowed)

	// no org selected
	res, err = authctx.GetCallerScope(requestCtx(identityFor(ownerID.String(), "", "")), a)
	require.NoError(t, err)
	assert.Empty(t, res.OrgID)
	assert.Equal(t, pb.Role_None, res.Role)
	assert.False(t, find(res, "/pb.Orgs/GetOrg").Allowed)
	assert.True(t, find(res, "/pb.Orgs/RegisterOrg").Allowed)

	// provider failure
	_, err = authctx.GetCallerScope(requestCtx(identityFor(ownerID.String(), org, "Owner")), authctx.NewAuthorizer(&mockGrants{err: errors.New("db down")}))
	assert.ErrorContains(t, err, "unable to get user memberships")
}

func Test_NewAuthUnaryInterceptor(t *testing.T) {
	t.Parallel()
	a := authctx.NewAuthorizer(specGrants())
	interceptor := authctx.NewAuthUnaryInterceptor(a, nil)

	handlerCalled := false
	handler := func(ctx context.Context, req any) (any, error) {
		handlerCalled = true
		tctx := authctx.FromContext(ctx)
		assert.Equal(t, ownerID.UInt64(), tctx.UserID().UInt64())
		assert.Equal(t, orgID.UInt64(), tctx.OrgID().UInt64())
		return "ok", nil
	}

	ctx := identity.AddToContext(context.Background(), identity.NewRequestContext(identityFor(ownerID.String(), orgID.String(), "Owner"), "/pb.Orgs/GetMembers"))
	res, err := interceptor(ctx, &pb.GetMembersRequest{}, &grpc.UnaryServerInfo{FullMethod: "/pb.Orgs/GetMembers"}, handler)
	require.NoError(t, err)
	assert.Equal(t, "ok", res)
	assert.True(t, handlerCalled)

	handlerCalled = false
	ctx = identity.AddToContext(context.Background(), identity.NewRequestContext(identityFor(strangerID.String(), orgID.String(), ""), "/pb.Orgs/GetMembers"))
	_, err = interceptor(ctx, &pb.GetMembersRequest{}, &grpc.UnaryServerInfo{FullMethod: "/pb.Orgs/GetMembers"}, handler)
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.False(t, handlerCalled)
}

// orgReq is a request that carries an explicit OrgID
type orgReq struct {
	orgID string
}

func (r *orgReq) GetOrgID() string { return r.orgID }
