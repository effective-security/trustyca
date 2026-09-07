package authctx_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/xhttp/httperror"
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
	"google.golang.org/protobuf/types/known/emptypb"
)

func Test_TrustyCtx(t *testing.T) {
	t.Parallel()
	userIDStr := "12345"
	orgIDStr := "23456"
	c := map[string]any{
		"sub":   userIDStr,
		"email": "denis@tbilicode.com",
		"name":  "Denis",
		"role":  "user",
		"orgs": map[string]string{
			orgIDStr: pb.Role_Admin.String(),
		},
	}
	uid := identity.NewIdentity("user", userIDStr, "", c, "accessToken", "Bearer", identity.MethodJWT)
	w, r, _ := testutils.CreateRequest(http.MethodGet, "/test", nil, uid)

	authCtx := authctx.FromRequest(r)
	assert.Equal(t, uint64(12345), authCtx.UserID().UInt64())
	assert.Equal(t, "user", authCtx.AppRole())
	assert.Equal(t, "Denis", authCtx.Name())
	assert.Equal(t, "denis@tbilicode.com", authCtx.Email())
	assert.Equal(t, identity.MethodJWT, authCtx.AuthMethod())
	assert.Len(t, authCtx.Memberships(), 1)
	assert.Equal(t, pb.Role_Admin, authCtx.Memberships()[orgIDStr])

	role := authctx.FindCallerRole(authCtx, orgIDStr)
	assert.Equal(t, pb.Role_Admin, role)

	role = authctx.FindCallerRole(authCtx, "12345")
	assert.Equal(t, pb.Role_None, role)

	role = authctx.FindCallerRole(authCtx, "1234567890")
	assert.Equal(t, pb.Role_None, role)

	h := func(w http.ResponseWriter, r *http.Request) {
		authCtx := authctx.FromRequest(r)
		assert.Equal(t, uint64(12345), authCtx.UserID().UInt64())
		w.WriteHeader(http.StatusOK)
	}

	au := authctx.Handler(http.HandlerFunc(h))
	au.ServeHTTP(w, r)
	// second time — context already present, Handler skips rebuild
	au.ServeHTTP(w, r)

	// Request with identity but no TrustyCtx yet — Handler builds it.
	r2, err := http.NewRequest(http.MethodGet, "/test", nil)
	require.NoError(t, err)
	r2 = identity.WithTestIdentity(r2, uid)
	assert.True(t, authctx.FromRequest(r2).UserID().IsZero())
	au.ServeHTTP(httptest.NewRecorder(), r2)
}

func Test_FromContext_Empty(t *testing.T) {
	t.Parallel()
	ctx := authctx.FromContext(context.Background())
	require.NotNil(t, ctx)
	assert.True(t, ctx.UserID().IsZero())
	assert.Empty(t, ctx.AppRole())
	assert.Empty(t, ctx.Name())
	assert.Empty(t, ctx.Email())
	assert.Empty(t, ctx.Target())
	assert.Empty(t, ctx.UserAgent())
	assert.Nil(t, ctx.Memberships())
}

func Test_NewTrustyCtx_Guest(t *testing.T) {
	t.Parallel()
	uid := identity.NewIdentity("guest", "", "", nil, "", "", identity.MethodNone)
	rc := identity.NewRequestContext(uid, "/pb.Orgs/GetMembers")
	ctx := authctx.NewTrustyCtx(context.Background(), rc)
	authCtx := authctx.FromContext(ctx)

	assert.Equal(t, "guest", authCtx.AppRole())
	assert.True(t, authCtx.UserID().IsZero())
	assert.Empty(t, authCtx.Name())
	assert.Empty(t, authCtx.Email())
	assert.Nil(t, authCtx.Memberships())
	assert.Equal(t, identity.MethodNone, authCtx.AuthMethod())
	assert.Equal(t, "/pb.Orgs/GetMembers", authCtx.Target())
}

func Test_NewTrustyCtx_RoleCaseVariants(t *testing.T) {
	t.Parallel()
	orgID := "100"
	cases := []struct {
		name     string
		roleStr  string
		wantRole pb.Role_Enum
	}{
		{"Admin", "Admin", pb.Role_Admin},
		{"admin", "admin", pb.Role_Admin},
		{"Owner", "Owner", pb.Role_Owner},
		{"owner", "owner", pb.Role_Owner},
		{"Support", "Support", pb.Role_Support},
		{"support", "support", pb.Role_Support},
		{"User", "User", pb.Role_User},
		{"user", "user", pb.Role_User},
		{"APIKey", "APIKey", pb.Role_APIKey},
		{"apikey", "apikey", pb.Role_APIKey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := map[string]any{
				"sub":   "42",
				"email": "u@tbilicode.com",
				"orgs": map[string]string{
					orgID: tc.roleStr,
				},
			}
			uid := identity.NewIdentity("user", "42", "", c, "tok", "Bearer", identity.MethodJWT)
			rc := identity.NewRequestContext(uid, "")
			authCtx := authctx.FromContext(authctx.NewTrustyCtx(context.Background(), rc))
			assert.Equal(t, tc.wantRole, authCtx.Memberships()[orgID])
		})
	}
}

func Test_CanAssumeRole(t *testing.T) {
	t.Parallel()

	assert.True(t, authctx.CanAssumeRole(pb.Role_User, []string{"User"}))
	assert.False(t, authctx.CanAssumeRole(pb.Role_User, []string{"Admin"}))
	assert.False(t, authctx.CanAssumeRole(pb.Role_User, []string{"APIKey"}))

	assert.True(t, authctx.CanAssumeRole(pb.Role_Support, []string{"Support"}))
	assert.True(t, authctx.CanAssumeRole(pb.Role_Support, []string{"User"}))
	assert.True(t, authctx.CanAssumeRole(pb.Role_Support, []string{"Admin", "Support"}))
	assert.False(t, authctx.CanAssumeRole(pb.Role_Support, []string{"Admin"}))
	assert.False(t, authctx.CanAssumeRole(pb.Role_Support, []string{"APIKey"}))
	assert.False(t, authctx.CanAssumeRole(pb.Role_Support, []string{"Owner"}))

	assert.True(t, authctx.CanAssumeRole(pb.Role_Admin, []string{"Admin"}))
	assert.True(t, authctx.CanAssumeRole(pb.Role_Admin, []string{"Support"}))
	assert.True(t, authctx.CanAssumeRole(pb.Role_Admin, []string{"User"}))
	assert.False(t, authctx.CanAssumeRole(pb.Role_Admin, []string{"Owner"}))
	assert.False(t, authctx.CanAssumeRole(pb.Role_Admin, []string{"APIKey"}))

	assert.True(t, authctx.CanAssumeRole(pb.Role_Owner, []string{"Owner"}))
	assert.True(t, authctx.CanAssumeRole(pb.Role_Owner, []string{"Admin"}))
	assert.True(t, authctx.CanAssumeRole(pb.Role_Owner, []string{"Support"}))
	assert.True(t, authctx.CanAssumeRole(pb.Role_Owner, []string{"User"}))
	assert.False(t, authctx.CanAssumeRole(pb.Role_Owner, []string{"APIKey"}))

	assert.True(t, authctx.CanAssumeRole(pb.Role_APIKey, []string{"APIKey"}))
	assert.False(t, authctx.CanAssumeRole(pb.Role_APIKey, []string{"User"}))

	assert.False(t, authctx.CanAssumeRole(pb.Role_None, []string{"User"}))
	assert.False(t, authctx.CanAssumeRole(pb.Role_Admin, nil))
	assert.False(t, authctx.CanAssumeRole(pb.Role_Admin, []string{"unknown"}))
}

func Test_CheckAccess(t *testing.T) {
	t.Parallel()

	orgID := xdb.NewID(1000000)
	ownerID := xdb.NewID(9000000)
	adminID := xdb.NewID(9000001)
	userID := xdb.NewID(9000002)
	supportID := xdb.NewID(9000004)

	var (
		ownerMember = &model.MembershipInfo{
			OrgID:   orgID,
			OrgName: "test project",
			UserID:  ownerID,
			Name:    "Owner User",
			Email:   "owner@tbilicode.com",
			Role:    pb.Role_Owner,
		}
		adminMember = &model.MembershipInfo{
			OrgID:   orgID,
			OrgName: "test project",
			UserID:  adminID,
			Name:    "Admin User",
			Email:   "admin@tbilicode.com",
			Role:    pb.Role_Admin,
		}
		userMember = &model.MembershipInfo{
			OrgID:   orgID,
			OrgName: "test project",
			UserID:  userID,
			Name:    "Regular User",
			Email:   "user@tbilicode.com",
			Role:    pb.Role_User,
		}
		supportMember = &model.MembershipInfo{
			OrgID:   orgID,
			OrgName: "test project",
			UserID:  supportID,
			Name:    "Support User",
			Email:   "support@tbilicode.com",
			Role:    pb.Role_Support,
		}
	)

	mock := mockAccess{
		members: []*model.MembershipInfo{ownerMember, adminMember, userMember, supportMember},
	}

	t.Run("admin_role", func(t *testing.T) {
		roles := []*model.MembershipInfo{
			adminMember,
		}
		for _, role := range roles {
			c := map[string]any{
				"sub":   role.UserID.String(),
				"email": role.Email,
				"orgs": map[string]string{
					orgID.String(): role.Role.String(),
				},
			}
			uid := identity.NewIdentity("user", role.UserID.String(), "", c, "accessToken", "Bearer", identity.MethodJWT)
			_, r, _ := testutils.CreateRequest(http.MethodGet, "/test", nil, uid)

			err := authctx.CheckAccess(r.Context(), &mock, &emptypb.Empty{}, "/pb.Notfound")
			assert.NoError(t, err)

			err = authctx.CheckAccess(r.Context(), &mock, &pb.GetMembersRequest{OrgID: orgID.String()}, "/pb.Orgs/GetMembers")
			assert.NoError(t, err)

			err = authctx.CheckAccess(r.Context(), &mock, &pb.DeleteMemberRequest{OrgID: orgID.String()}, "/pb.Orgs/DeleteMember")
			assert.NoError(t, err)

			err = authctx.CheckAccess(r.Context(), &mock, &pb.DeleteInviteRequest{OrgID: orgID.String()}, "/pb.Orgs/DeleteInvite")
			assert.NoError(t, err)

			err = authctx.CheckAccess(r.Context(), &mock, &pb.AddMemberRequest{OrgID: orgID.String(), Email: role.Email, Role: role.Role}, "/pb.Orgs/AddMember")
			assert.NoError(t, err)

			err = authctx.CheckAccess(r.Context(), &mock, &pb.ChangeMemberRoleRequest{OrgID: orgID.String()}, "/pb.Orgs/ChangeMemberRole")
			assert.NoError(t, err)
		}
	})

	t.Run("owner_role", func(t *testing.T) {
		c := map[string]any{
			"sub":   ownerMember.UserID.String(),
			"email": ownerMember.Email,
			"orgs": map[string]string{
				orgID.String(): ownerMember.Role.String(),
			},
		}
		uid := identity.NewIdentity("user", ownerMember.UserID.String(), "", c, "accessToken", "Bearer", identity.MethodJWT)
		_, r, _ := testutils.CreateRequest(http.MethodGet, "/test", nil, uid)

		err := authctx.CheckAccess(r.Context(), &mock, &pb.GetMembersRequest{OrgID: orgID.String()}, "/pb.Orgs/GetMembers")
		assert.NoError(t, err)

		err = authctx.CheckAccess(r.Context(), &mock, &pb.AddMemberRequest{OrgID: orgID.String(), Email: ownerMember.Email, Role: pb.Role_User}, "/pb.Orgs/AddMember")
		assert.NoError(t, err)
	})

	t.Run("admin_role_wrong_org", func(t *testing.T) {
		roles := []*model.MembershipInfo{
			adminMember,
		}
		for _, role := range roles {
			c := map[string]any{
				"sub":   role.UserID.String(),
				"email": role.Email,
				"orgs": map[string]string{
					"1243524525": role.Role.String(),
				},
			}
			uid := identity.NewIdentity("user", role.UserID.String(), "", c, "accessToken", "Bearer", identity.MethodJWT)
			_, r, _ := testutils.CreateRequest(http.MethodGet, "/test", nil, uid)

			err := authctx.CheckAccess(r.Context(), &mock, &emptypb.Empty{}, "/pb.Notfound")
			assert.NoError(t, err)

			err = authctx.CheckAccess(r.Context(), &mock, &pb.GetMembersRequest{OrgID: orgID.String()}, "/pb.Orgs/GetMembers")
			assert.EqualError(t, err, "unauthorized: insufficient role: None, action: /pb.Orgs/GetMembers")

			err = authctx.CheckAccess(r.Context(), &mock, &pb.DeleteMemberRequest{OrgID: orgID.String()}, "/pb.Orgs/DeleteMember")
			assert.EqualError(t, err, "unauthorized: insufficient role: None, action: /pb.Orgs/DeleteMember")

			err = authctx.CheckAccess(r.Context(), &mock, &pb.DeleteInviteRequest{OrgID: orgID.String()}, "/pb.Orgs/DeleteInvite")
			assert.EqualError(t, err, "unauthorized: insufficient role: None, action: /pb.Orgs/DeleteInvite")

			err = authctx.CheckAccess(r.Context(), &mock, &pb.AddMemberRequest{OrgID: orgID.String(), Email: role.Email, Role: role.Role}, "/pb.Orgs/AddMember")
			assert.EqualError(t, err, "unauthorized: insufficient role: None, action: /pb.Orgs/AddMember")
		}
	})

	t.Run("support_role", func(t *testing.T) {
		roles := []*model.MembershipInfo{
			supportMember,
		}
		for _, role := range roles {
			c := map[string]any{
				"sub":   role.UserID.String(),
				"email": role.Email,
				"orgs": map[string]string{
					orgID.String(): role.Role.String(),
				},
			}
			uid := identity.NewIdentity("user", role.UserID.String(), "", c, "accessToken", "Bearer", identity.MethodJWT)
			_, r, _ := testutils.CreateRequest(http.MethodGet, "/test", nil, uid)

			err := authctx.CheckAccess(r.Context(), &mock, &emptypb.Empty{}, "/pb.Notfound")
			assert.NoError(t, err)

			err = authctx.CheckAccess(r.Context(), &mock, &pb.GetMembersRequest{OrgID: orgID.String()}, "/pb.Orgs/GetMembers")
			assert.NoError(t, err)

			err = authctx.CheckAccess(r.Context(), &mock, &pb.DeleteMemberRequest{OrgID: orgID.String()}, "/pb.Orgs/DeleteMember")
			assert.NoError(t, err)

			err = authctx.CheckAccess(r.Context(), &mock, &pb.DeleteInviteRequest{OrgID: orgID.String()}, "/pb.Orgs/DeleteInvite")
			assert.NoError(t, err)

			err = authctx.CheckAccess(r.Context(), &mock, &pb.AddMemberRequest{OrgID: orgID.String(), Email: role.Email, Role: role.Role}, "/pb.Orgs/AddMember")
			assert.NoError(t, err)
		}
	})

	t.Run("user_role", func(t *testing.T) {
		roles := []*model.MembershipInfo{
			userMember,
		}
		for _, role := range roles {
			c := map[string]any{
				"sub":   role.UserID.String(),
				"email": role.Email,
				"orgs": map[string]string{
					orgID.String(): role.Role.String(),
				},
			}
			uid := identity.NewIdentity("user", role.UserID.String(), "", c, "accessToken", "Bearer", identity.MethodJWT)
			_, r, _ := testutils.CreateRequest(http.MethodGet, "/test", nil, uid)

			err := authctx.CheckAccess(r.Context(), &mock, &emptypb.Empty{}, "/pb.Notfound")
			assert.NoError(t, err)

			err = authctx.CheckAccess(r.Context(), &mock, &emptypb.Empty{}, "/pb.Orgs/GetUserMemberships")
			assert.NoError(t, err)

			err = authctx.CheckAccess(r.Context(), &mock, &pb.GetMembersRequest{OrgID: orgID.String()}, "/pb.Orgs/GetMembers")
			assert.EqualError(t, err, "unauthorized: insufficient role: User, action: /pb.Orgs/GetMembers")

			err = authctx.CheckAccess(r.Context(), &mock, &pb.DeleteMemberRequest{OrgID: orgID.String()}, "/pb.Orgs/DeleteMember")
			assert.EqualError(t, err, "unauthorized: insufficient role: User, action: /pb.Orgs/DeleteMember")

			err = authctx.CheckAccess(r.Context(), &mock, &pb.DeleteInviteRequest{OrgID: orgID.String()}, "/pb.Orgs/DeleteInvite")
			assert.EqualError(t, err, "unauthorized: insufficient role: User, action: /pb.Orgs/DeleteInvite")

			err = authctx.CheckAccess(r.Context(), &mock, &pb.AddMemberRequest{OrgID: orgID.String(), Email: role.Email, Role: role.Role}, "/pb.Orgs/AddMember")
			assert.EqualError(t, err, "unauthorized: insufficient role: User, action: /pb.Orgs/AddMember")
		}
	})

	t.Run("guest_unauthenticated", func(t *testing.T) {
		uid := identity.NewIdentity("guest", "", "", nil, "", "", identity.MethodNone)
		_, r, _ := testutils.CreateRequest(http.MethodGet, "/test", nil, uid)

		err := authctx.CheckAccess(r.Context(), &mock, &pb.GetMembersRequest{OrgID: orgID.String()}, "/pb.Orgs/GetMembers")
		assert.EqualError(t, err, "unauthorized: access denied")

		err = authctx.CheckAccess(r.Context(), &mock, &emptypb.Empty{}, "/pb.Orgs/GetUserMemberships")
		assert.NoError(t, err)
	})

	t.Run("empty_role_unauthenticated", func(t *testing.T) {
		uid := identity.NewIdentity("", "1", "", map[string]any{"sub": "1"}, "", "", identity.MethodJWT)
		_, r, _ := testutils.CreateRequest(http.MethodGet, "/test", nil, uid)

		err := authctx.CheckAccess(r.Context(), &mock, &pb.GetMembersRequest{OrgID: orgID.String()}, "/pb.Orgs/GetMembers")
		assert.EqualError(t, err, "unauthorized: access denied")
	})

	t.Run("fallback_to_role_checker", func(t *testing.T) {
		// No projects claim → Memberships() is nil → CheckAccess consults RoleChecker.
		c := map[string]any{
			"sub":   adminMember.UserID.String(),
			"email": adminMember.Email,
		}
		uid := identity.NewIdentity("user", adminMember.UserID.String(), "", c, "accessToken", "Bearer", identity.MethodJWT)
		_, r, _ := testutils.CreateRequest(http.MethodGet, "/test", nil, uid)
		assert.Nil(t, authctx.FromRequest(r).Memberships())

		err := authctx.CheckAccess(r.Context(), &mock, &pb.GetMembersRequest{OrgID: orgID.String()}, "/pb.Orgs/GetMembers")
		assert.NoError(t, err)

		err = authctx.CheckAccess(r.Context(), &mock, &pb.GetMembersRequest{OrgID: "999"}, "/pb.Orgs/GetMembers")
		assert.Error(t, err)
	})

	t.Run("non_project_request_with_roles", func(t *testing.T) {
		c := map[string]any{
			"sub":   userMember.UserID.String(),
			"email": userMember.Email,
			"orgs": map[string]string{
				orgID.String(): userMember.Role.String(),
			},
		}
		uid := identity.NewIdentity("user", userMember.UserID.String(), "", c, "accessToken", "Bearer", identity.MethodJWT)
		_, r, _ := testutils.CreateRequest(http.MethodGet, "/test", nil, uid)

		// Authenticated, AllowedRoles set, but request has no ProjectID — no role check runs.
		err := authctx.CheckAccess(r.Context(), &mock, &emptypb.Empty{}, "/pb.Orgs/GetMembers")
		assert.NoError(t, err)
	})
}

func Test_NewAuthUnaryInterceptor(t *testing.T) {
	t.Parallel()

	projectID := xdb.NewID(1000000)
	adminID := xdb.NewID(9000001)
	adminMember := &model.MembershipInfo{
		OrgID:  projectID,
		UserID: adminID,
		Email:  "admin@tbilicode.com",
		Role:   pb.Role_Admin,
	}
	mock := &mockAccess{members: []*model.MembershipInfo{adminMember}}

	interceptor := authctx.NewAuthUnaryInterceptor(mock, nil)

	t.Run("allowed", func(t *testing.T) {
		c := map[string]any{
			"sub":   adminID.String(),
			"email": adminMember.Email,
			"orgs": map[string]string{
				projectID.String(): pb.Role_Admin.String(),
			},
		}
		uid := identity.NewIdentity("user", adminID.String(), "", c, "tok", "Bearer", identity.MethodJWT)
		rc := identity.NewRequestContext(uid, "")
		ctx := identity.AddToContext(context.Background(), rc)

		called := false
		resp, err := interceptor(ctx, &pb.GetMembersRequest{OrgID: projectID.String()},
			&grpc.UnaryServerInfo{FullMethod: "/pb.Orgs/GetMembers"},
			func(ctx context.Context, req any) (any, error) {
				called = true
				assert.Equal(t, adminID.UInt64(), authctx.FromContext(ctx).UserID().UInt64())
				return "ok", nil
			})
		require.NoError(t, err)
		assert.True(t, called)
		assert.Equal(t, "ok", resp)
	})

	t.Run("denied", func(t *testing.T) {
		uid := identity.NewIdentity("guest", "", "", nil, "", "", identity.MethodNone)
		rc := identity.NewRequestContext(uid, "")
		ctx := identity.AddToContext(context.Background(), rc)

		called := false
		_, err := interceptor(ctx, &pb.GetMembersRequest{OrgID: projectID.String()},
			&grpc.UnaryServerInfo{FullMethod: "/pb.Orgs/GetMembers"},
			func(ctx context.Context, req any) (any, error) {
				called = true
				return nil, nil
			})
		assert.EqualError(t, err, "unauthorized: access denied")
		assert.False(t, called)
	})
}

func Test_RoleChecker(t *testing.T) {
	t.Parallel()

	orgID := xdb.NewID(1000000)
	adminID := xdb.NewID(9000001)
	userID := xdb.NewID(9000002)
	otherOrgID := xdb.NewID(2000000)

	adminMember := &model.MembershipInfo{
		ID:      xdb.NewID(1),
		OrgID:   orgID,
		OrgName: "org",
		UserID:  adminID,
		Name:    "Admin",
		Email:   "admin@tbilicode.com",
		Role:    pb.Role_Admin,
	}
	userMember := &model.MembershipInfo{
		ID:      xdb.NewID(2),
		OrgID:   orgID,
		OrgName: "org",
		UserID:  userID,
		Name:    "User",
		Email:   "user@tbilicode.com",
		Role:    pb.Role_User,
	}

	provider := &mockMembership{
		byUser: map[uint64]model.MembershipInfoSlice{
			adminID.UInt64(): {adminMember},
			userID.UInt64():  {userMember},
		},
	}
	checker := authctx.NewRoleChecker(provider)

	t.Run("admin_allowed", func(t *testing.T) {
		m, err := checker.CheckRole(context.Background(), orgID.String(), adminID, "Admin", "Support")
		require.NoError(t, err)
		require.NotNil(t, m)
		assert.Equal(t, pb.Role_Admin, m.Role)
		assert.Equal(t, 1, provider.calls)
	})

	t.Run("cached_second_call", func(t *testing.T) {
		before := provider.calls
		m, err := checker.CheckRole(context.Background(), orgID.String(), adminID, "Admin")
		require.NoError(t, err)
		require.NotNil(t, m)
		assert.Equal(t, before, provider.calls, "memberships should be served from cache")
	})

	t.Run("user_denied", func(t *testing.T) {
		m, err := checker.CheckRole(context.Background(), orgID.String(), userID, "Admin", "Support")
		assert.Nil(t, m)
		assert.EqualError(t, err, "insufficient role")
	})

	t.Run("wrong_project", func(t *testing.T) {
		m, err := checker.CheckRole(context.Background(), otherOrgID.String(), adminID, "Admin")
		assert.Nil(t, m)
		assert.EqualError(t, err, "insufficient role")
	})

	t.Run("invalid_project_id", func(t *testing.T) {
		m, err := checker.CheckRole(context.Background(), "not-a-number", adminID, "Admin")
		assert.Nil(t, m)
		assert.ErrorContains(t, err, "invalid org ID")
	})

	t.Run("provider_error", func(t *testing.T) {
		failing := &mockMembership{err: errors.New("db down")}
		c := authctx.NewRoleChecker(failing)
		m, err := c.CheckRole(context.Background(), orgID.String(), adminID, "Admin")
		assert.Nil(t, m)
		assert.ErrorContains(t, err, "unable to get user memberships")
	})
}

type mockAccess struct {
	members []*model.MembershipInfo
}

// CheckRole returns an error if a caller does not have access
func (m *mockAccess) CheckRole(ctx context.Context, orgID string, callerID xdb.ID, roles ...string) (*model.MembershipInfo, error) {
	for _, member := range m.members {
		if member.OrgID.String() == orgID &&
			member.UserID.UInt64() == callerID.UInt64() &&
			authctx.CanAssumeRole(member.Role, roles) {
			m := &model.MembershipInfo{
				ID:      member.ID,
				OrgID:   member.OrgID,
				OrgName: member.OrgName,
				UserID:  member.UserID,
				Role:    member.Role,
			}
			return m, nil
		}
	}

	return nil, httperror.NewGrpcFromCtx(ctx, codes.PermissionDenied, "insufficient role")
}

func (m *mockAccess) InvalidateCache(ctx context.Context, userID string) {
}

type mockMembership struct {
	byUser map[uint64]model.MembershipInfoSlice
	err    error
	calls  int
}

func (m *mockMembership) ListMemberships(ctx context.Context, req *query.ListMembershipsRequest) (model.MembershipInfoSlice, error) {
	m.calls++
	if m.err != nil {
		return nil, m.err
	}
	return m.byUser[req.UserID], nil
}
