package orgs

import (
	"context"
	"database/sql"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/xhttp/identity"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/authctx"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/mocks/mocktrustycadb"
	"github.com/effective-security/xdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"google.golang.org/protobuf/types/known/emptypb"
)

func testTrustyCtx(userID, orgID, role string) context.Context {
	claims := map[string]any{
		"sub":   userID,
		"email": "caller@example.com",
		"name":  "Caller",
	}
	if orgID != "" {
		claims["orgs"] = map[string]string{
			orgID: role,
		}
	}
	uid := identity.NewIdentity("user", userID, "", claims, "tok", "Bearer", identity.MethodJWT)
	return authctx.NewTrustyCtx(context.Background(), identity.NewRequestContext(uid, ""))
}

func TestService_GetUserMemberships(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := mocktrustycadb.NewMockOrgsDb(ctrl)
	svc := Service{
		db:          db,
		roleChecker: authctx.NewRoleChecker(db),
	}

	memberships := model.MembershipInfoSlice{
		{
			ID:        xdb.NewID(10),
			OrgID:     xdb.NewID(1),
			OrgName:   "Test Org",
			UserID:    xdb.NewID(42),
			Email:     "caller@example.com",
			Name:      "Caller",
			Role:      pb.Role_Owner,
			CreatedAt: xdb.ParseTime("2020-01-01"),
		},
	}

	ctx := testTrustyCtx("42", "1", pb.Role_Owner.String())
	db.EXPECT().ListMemberships(gomock.Any(), &query.ListMembershipsRequest{UserID: 42, OrgStatus: pb.ItemStatus_Active}).Return(memberships, nil)

	res, err := svc.GetUserMemberships(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	require.Len(t, res.Memberships, 1)
	assert.Equal(t, "10", res.Memberships[0].ID)
	assert.Equal(t, "1", res.Memberships[0].OrgID)
	assert.Equal(t, "Test Org", res.Memberships[0].OrgName)
	assert.Equal(t, "42", res.Memberships[0].UserID)
	assert.Equal(t, pb.Role_Owner, res.Memberships[0].Role)

	db.EXPECT().ListMemberships(gomock.Any(), &query.ListMembershipsRequest{UserID: 42, OrgStatus: pb.ItemStatus_Active}).Return(nil, errors.New("db failed"))
	_, err = svc.GetUserMemberships(ctx, &emptypb.Empty{})
	require.Error(t, err)
	assert.EqualError(t, err, "db failed")
}

func TestService_GetMembers(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := mocktrustycadb.NewMockOrgsDb(ctrl)
	svc := Service{
		db:          db,
		roleChecker: authctx.NewRoleChecker(db),
	}

	ctx := context.Background()

	memberships := model.MembershipInfoSlice{
		{
			ID:      xdb.NewID(10),
			OrgID:   xdb.NewID(1),
			OrgName: "Test Org",
			UserID:  xdb.NewID(42),
			Email:   "owner@example.com",
			Name:    "Owner",
			Role:    pb.Role_Owner,
		},
	}
	invites := model.InviteSlice{
		{
			ID:        xdb.NewID(20),
			OrgID:     xdb.NewID(1),
			InviterID: xdb.NewID(42),
			Email:     "invitee@example.com",
			Role:      pb.Role_User,
		},
	}

	db.EXPECT().ListMemberships(gomock.Any(), gomock.Any()).Return(memberships, nil)
	db.EXPECT().GetOrgInvites(gomock.Any(), uint64(1)).Return(invites, nil)

	res, err := svc.GetMembers(ctx, &pb.GetMembersRequest{OrgID: "1"})
	require.NoError(t, err)
	require.Len(t, res.Memberships, 1)
	assert.Equal(t, "10", res.Memberships[0].ID)
	assert.Equal(t, pb.Role_Owner, res.Memberships[0].Role)
	require.Len(t, res.Invites, 1)
	assert.Equal(t, "20", res.Invites[0].ID)
	assert.Equal(t, "invitee@example.com", res.Invites[0].Email)

	_, err = svc.GetMembers(ctx, &pb.GetMembersRequest{})
	require.Error(t, err)
	assert.EqualError(t, err, "bad_request: invalid org ID")

	db.EXPECT().ListMemberships(gomock.Any(), gomock.Any()).Return(nil, errors.New("db failed"))
	_, err = svc.GetMembers(ctx, &pb.GetMembersRequest{OrgID: "1"})
	require.Error(t, err)
	assert.EqualError(t, err, "db failed")

	db.EXPECT().ListMemberships(gomock.Any(), gomock.Any()).Return(memberships, nil)
	db.EXPECT().GetOrgInvites(gomock.Any(), uint64(1)).Return(nil, errors.New("db failed"))
	_, err = svc.GetMembers(ctx, &pb.GetMembersRequest{OrgID: "1"})
	require.Error(t, err)
	assert.EqualError(t, err, "db failed")
}

func TestService_AddMember(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := mocktrustycadb.NewMockOrgsDb(ctrl)
	svc := Service{
		db:          db,
		roleChecker: authctx.NewRoleChecker(db),
	}

	org := &model.Org{
		ID:     xdb.NewID(1),
		Name:   "Test Org",
		Status: pb.ItemStatus_Active,
	}
	user := &model.User{
		ID:    xdb.NewID(7),
		Email: "user@example.com",
		Name:  "User Name",
	}
	member := &model.Membership{
		ID:        xdb.NewID(10),
		OrgID:     org.ID,
		UserID:    user.ID,
		Role:      pb.Role_Admin,
		CreatedAt: xdb.ParseTime("2020-01-01"),
	}
	existing := model.MembershipInfoSlice{
		{
			ID:     xdb.NewID(11),
			OrgID:  org.ID,
			UserID: user.ID,
			Email:  user.Email,
			Name:   user.Name,
			Role:   pb.Role_Admin,
		},
	}
	invite := &model.Invite{
		ID:        xdb.NewID(20),
		OrgID:     org.ID,
		InviterID: xdb.NewID(42),
		Email:     "new@example.com",
		Role:      pb.Role_User,
		CreatedAt: xdb.ParseTime("2020-01-01"),
	}

	ownerCtx := testTrustyCtx("42", "1", pb.Role_Owner.String())
	adminCtx := testTrustyCtx("42", "1", pb.Role_Admin.String())

	_, err := svc.AddMember(ownerCtx, &pb.AddMemberRequest{})
	require.Error(t, err)
	assert.EqualError(t, err, "bad_request: invalid org ID")

	_, err = svc.AddMember(ownerCtx, &pb.AddMemberRequest{OrgID: "1"})
	require.Error(t, err)
	assert.EqualError(t, err, "bad_request: email is required")

	_, err = svc.AddMember(adminCtx, &pb.AddMemberRequest{
		OrgID: "1",
		Email: "user@example.com",
		Role:  pb.Role_Owner,
	})
	require.Error(t, err)
	assert.EqualError(t, err, "unauthorized: owner role required")

	db.EXPECT().GetOrg(gomock.Any(), uint64(1)).Return(nil, errors.New("not found"))
	_, err = svc.AddMember(ownerCtx, &pb.AddMemberRequest{
		OrgID: "1",
		Email: "user@example.com",
		Role:  pb.Role_Admin,
	})
	require.Error(t, err)
	assert.EqualError(t, err, "not_found: unable to find org")

	db.EXPECT().GetOrg(gomock.Any(), uint64(1)).Return(&model.Org{
		ID:     xdb.NewID(1),
		Status: pb.ItemStatus_Inactive,
	}, nil)
	_, err = svc.AddMember(ownerCtx, &pb.AddMemberRequest{
		OrgID: "1",
		Email: "user@example.com",
		Role:  pb.Role_Admin,
	})
	require.Error(t, err)
	assert.EqualError(t, err, "unexpected: org is deleted")

	db.EXPECT().GetOrg(gomock.Any(), uint64(1)).Return(org, nil)
	db.EXPECT().GetUserByEmail(gomock.Any(), "user@example.com").Return(user, nil)
	db.EXPECT().ListMemberships(gomock.Any(), gomock.Any()).Return(nil, errors.New("db failed"))
	_, err = svc.AddMember(ownerCtx, &pb.AddMemberRequest{
		OrgID: "1",
		Email: "  User@Example.com  ",
		Role:  pb.Role_Admin,
	})
	require.Error(t, err)
	assert.EqualError(t, err, "unexpected: request failed")

	db.EXPECT().GetOrg(gomock.Any(), uint64(1)).Return(org, nil)
	db.EXPECT().GetUserByEmail(gomock.Any(), "user@example.com").Return(user, nil)
	db.EXPECT().ListMemberships(gomock.Any(), gomock.Any()).Return(existing, nil)
	res, err := svc.AddMember(ownerCtx, &pb.AddMemberRequest{
		OrgID: "1",
		Email: "user@example.com",
		Role:  pb.Role_Admin,
	})
	require.NoError(t, err)
	require.NotNil(t, res.Membership)
	assert.Equal(t, "11", res.Membership.ID)
	assert.Equal(t, pb.Role_Admin, res.Membership.Role)
	assert.Nil(t, res.Invite)

	db.EXPECT().GetOrg(gomock.Any(), uint64(1)).Return(org, nil)
	db.EXPECT().GetUserByEmail(gomock.Any(), "user@example.com").Return(user, nil)
	db.EXPECT().ListMemberships(gomock.Any(), gomock.Any()).Return(existing, nil)
	_, err = svc.AddMember(ownerCtx, &pb.AddMemberRequest{
		OrgID: "1",
		Email: "user@example.com",
		Role:  pb.Role_User,
	})
	require.Error(t, err)
	assert.EqualError(t, err, "conflict: user already member")

	db.EXPECT().GetOrg(gomock.Any(), uint64(1)).Return(org, nil)
	db.EXPECT().GetUserByEmail(gomock.Any(), "user@example.com").Return(user, nil)
	db.EXPECT().ListMemberships(gomock.Any(), gomock.Any()).Return(nil, nil)
	db.EXPECT().AddMember(gomock.Any(), gomock.Any()).Return(nil, errors.New("db failed"))
	_, err = svc.AddMember(ownerCtx, &pb.AddMemberRequest{
		OrgID: "1",
		Email: "user@example.com",
		Role:  pb.Role_Admin,
	})
	require.Error(t, err)
	assert.EqualError(t, err, "unexpected: request failed")

	db.EXPECT().GetOrg(gomock.Any(), uint64(1)).Return(org, nil)
	db.EXPECT().GetUserByEmail(gomock.Any(), "user@example.com").Return(user, nil)
	db.EXPECT().ListMemberships(gomock.Any(), gomock.Any()).Return(nil, nil)
	db.EXPECT().AddMember(gomock.Any(), gomock.Any()).Return(member, nil)
	res, err = svc.AddMember(ownerCtx, &pb.AddMemberRequest{
		OrgID: "1",
		Email: "user@example.com",
		Role:  pb.Role_Admin,
	})
	require.NoError(t, err)
	require.NotNil(t, res.Membership)
	assert.Equal(t, "10", res.Membership.ID)
	assert.Equal(t, "1", res.Membership.OrgID)
	assert.Equal(t, "Test Org", res.Membership.OrgName)
	assert.Equal(t, "7", res.Membership.UserID)
	assert.Equal(t, "user@example.com", res.Membership.Email)
	assert.Equal(t, "User Name", res.Membership.Name)
	assert.Equal(t, pb.Role_Admin, res.Membership.Role)
	assert.Nil(t, res.Invite)

	db.EXPECT().GetOrg(gomock.Any(), uint64(1)).Return(org, nil)
	db.EXPECT().GetUserByEmail(gomock.Any(), "new@example.com").Return(nil, sql.ErrNoRows)
	db.EXPECT().CreateInvite(gomock.Any(), gomock.Any()).Return(nil, errors.New("db failed"))
	_, err = svc.AddMember(ownerCtx, &pb.AddMemberRequest{
		OrgID: "1",
		Email: "new@example.com",
		Role:  pb.Role_User,
	})
	require.Error(t, err)
	assert.EqualError(t, err, "unexpected: request failed")

	db.EXPECT().GetOrg(gomock.Any(), uint64(1)).Return(org, nil)
	db.EXPECT().GetUserByEmail(gomock.Any(), "new@example.com").Return(nil, sql.ErrNoRows)
	db.EXPECT().CreateInvite(gomock.Any(), gomock.Any()).Return(invite, nil)
	res, err = svc.AddMember(ownerCtx, &pb.AddMemberRequest{
		OrgID: "1",
		Email: "new@example.com",
		Role:  pb.Role_User,
	})
	require.NoError(t, err)
	require.NotNil(t, res.Invite)
	assert.Equal(t, "20", res.Invite.ID)
	assert.Equal(t, "1", res.Invite.OrgID)
	assert.Equal(t, "42", res.Invite.InviterID)
	assert.Equal(t, "new@example.com", res.Invite.Email)
	assert.Equal(t, pb.Role_User, res.Invite.Role)
	assert.Nil(t, res.Membership)

	db.EXPECT().GetOrg(gomock.Any(), uint64(1)).Return(org, nil)
	db.EXPECT().GetUserByEmail(gomock.Any(), "new@example.com").Return(nil, errors.New("connection failed"))
	db.EXPECT().CreateInvite(gomock.Any(), gomock.Any()).Return(invite, nil)
	res, err = svc.AddMember(ownerCtx, &pb.AddMemberRequest{
		OrgID: "1",
		Email: "new@example.com",
		Role:  pb.Role_User,
	})
	require.NoError(t, err)
	require.NotNil(t, res.Invite)
	assert.Equal(t, "new@example.com", res.Invite.Email)
}

func TestService_ChangeMemberRole(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := mocktrustycadb.NewMockOrgsDb(ctrl)
	svc := Service{
		db:          db,
		roleChecker: authctx.NewRoleChecker(db),
	}

	org := &model.Org{
		ID:     xdb.NewID(1),
		Name:   "Test Org",
		Status: pb.ItemStatus_Active,
	}
	user := &model.User{
		ID:    xdb.NewID(7),
		Email: "user@example.com",
		Name:  "User Name",
	}
	adminMember := &model.MembershipInfo{
		ID:     xdb.NewID(10),
		OrgID:  org.ID,
		UserID: user.ID,
		Email:  user.Email,
		Name:   user.Name,
		Role:   pb.Role_Admin,
	}
	ownerMember := &model.MembershipInfo{
		ID:     xdb.NewID(11),
		OrgID:  org.ID,
		UserID: xdb.NewID(42),
		Email:  "owner@example.com",
		Name:   "Owner",
		Role:   pb.Role_Owner,
	}
	updated := &model.Membership{
		ID:        adminMember.ID,
		OrgID:     org.ID,
		UserID:    user.ID,
		Role:      pb.Role_User,
		CreatedAt: xdb.ParseTime("2020-01-01"),
	}

	ownerCtx := testTrustyCtx("42", "1", pb.Role_Owner.String())
	adminCtx := testTrustyCtx("7", "1", pb.Role_Admin.String())

	_, err := svc.ChangeMemberRole(ownerCtx, &pb.ChangeMemberRoleRequest{})
	require.Error(t, err)
	assert.EqualError(t, err, "bad_request: invalid org ID")

	_, err = svc.ChangeMemberRole(adminCtx, &pb.ChangeMemberRoleRequest{
		OrgID:  "1",
		UserID: "7",
		Role:   pb.Role_Owner,
	})
	require.Error(t, err)
	assert.EqualError(t, err, "unauthorized: forbidden to change owner")

	db.EXPECT().ListMemberships(gomock.Any(), gomock.Any()).Return(nil, errors.New("db failed"))
	_, err = svc.ChangeMemberRole(ownerCtx, &pb.ChangeMemberRoleRequest{
		OrgID:  "1",
		UserID: "7",
		Role:   pb.Role_User,
	})
	require.Error(t, err)
	assert.EqualError(t, err, "unexpected: request failed")

	db.EXPECT().ListMemberships(gomock.Any(), gomock.Any()).Return(model.MembershipInfoSlice{adminMember}, nil)
	_, err = svc.ChangeMemberRole(ownerCtx, &pb.ChangeMemberRoleRequest{
		OrgID:  "1",
		UserID: "bad",
		Role:   pb.Role_User,
	})
	require.Error(t, err)
	assert.EqualError(t, err, "bad_request: invalid user ID")

	db.EXPECT().ListMemberships(gomock.Any(), gomock.Any()).Return(model.MembershipInfoSlice{adminMember}, nil)
	_, err = svc.ChangeMemberRole(ownerCtx, &pb.ChangeMemberRoleRequest{
		OrgID: "1",
		Role:  pb.Role_User,
	})
	require.Error(t, err)
	assert.EqualError(t, err, "unexpected: unable to find user")

	db.EXPECT().ListMemberships(gomock.Any(), gomock.Any()).Return(model.MembershipInfoSlice{ownerMember}, nil)
	_, err = svc.ChangeMemberRole(adminCtx, &pb.ChangeMemberRoleRequest{
		OrgID:  "1",
		UserID: "42",
		Role:   pb.Role_Admin,
	})
	require.Error(t, err)
	assert.EqualError(t, err, "unauthorized: forbidden to change owner")

	db.EXPECT().ListMemberships(gomock.Any(), gomock.Any()).Return(model.MembershipInfoSlice{adminMember}, nil)
	db.EXPECT().GetOrg(gomock.Any(), uint64(1)).Return(nil, errors.New("not found"))
	_, err = svc.ChangeMemberRole(ownerCtx, &pb.ChangeMemberRoleRequest{
		OrgID:  "1",
		UserID: "7",
		Role:   pb.Role_User,
	})
	require.Error(t, err)
	assert.EqualError(t, err, "not_found: unable to find org")

	db.EXPECT().ListMemberships(gomock.Any(), gomock.Any()).Return(model.MembershipInfoSlice{adminMember}, nil)
	db.EXPECT().GetOrg(gomock.Any(), uint64(1)).Return(&model.Org{
		ID:     xdb.NewID(1),
		Status: pb.ItemStatus_Inactive,
	}, nil)
	_, err = svc.ChangeMemberRole(ownerCtx, &pb.ChangeMemberRoleRequest{
		OrgID:  "1",
		UserID: "7",
		Role:   pb.Role_User,
	})
	require.Error(t, err)
	assert.EqualError(t, err, "unexpected: org is deleted")

	db.EXPECT().ListMemberships(gomock.Any(), gomock.Any()).Return(model.MembershipInfoSlice{adminMember}, nil)
	db.EXPECT().GetOrg(gomock.Any(), uint64(1)).Return(org, nil)
	db.EXPECT().GetUser(gomock.Any(), uint64(7)).Return(nil, errors.New("not found"))
	_, err = svc.ChangeMemberRole(ownerCtx, &pb.ChangeMemberRoleRequest{
		OrgID: "1",
		Email: "user@example.com",
		Role:  pb.Role_User,
	})
	require.Error(t, err)
	assert.EqualError(t, err, "not_found: unable to find user")

	db.EXPECT().ListMemberships(gomock.Any(), gomock.Any()).Return(model.MembershipInfoSlice{adminMember}, nil)
	db.EXPECT().GetOrg(gomock.Any(), uint64(1)).Return(org, nil)
	db.EXPECT().GetUser(gomock.Any(), uint64(7)).Return(user, nil)
	db.EXPECT().UpdateMemberRole(gomock.Any(), uint64(1), uint64(7), pb.Role_User).Return(nil, errors.New("db failed"))
	_, err = svc.ChangeMemberRole(ownerCtx, &pb.ChangeMemberRoleRequest{
		OrgID:  "1",
		UserID: "7",
		Role:   pb.Role_User,
	})
	require.Error(t, err)
	assert.EqualError(t, err, "unexpected: request failed")

	db.EXPECT().ListMemberships(gomock.Any(), gomock.Any()).Return(model.MembershipInfoSlice{adminMember}, nil)
	db.EXPECT().GetOrg(gomock.Any(), uint64(1)).Return(org, nil)
	db.EXPECT().GetUser(gomock.Any(), uint64(7)).Return(user, nil)
	db.EXPECT().UpdateMemberRole(gomock.Any(), uint64(1), uint64(7), pb.Role_User).Return(updated, nil)
	res, err := svc.ChangeMemberRole(ownerCtx, &pb.ChangeMemberRoleRequest{
		OrgID:  "1",
		UserID: "7",
		Role:   pb.Role_User,
	})
	require.NoError(t, err)
	assert.Equal(t, "10", res.ID)
	assert.Equal(t, "1", res.OrgID)
	assert.Equal(t, "Test Org", res.OrgName)
	assert.Equal(t, "7", res.UserID)
	assert.Equal(t, "user@example.com", res.Email)
	assert.Equal(t, "User Name", res.Name)
	assert.Equal(t, pb.Role_User, res.Role)
}

func TestService_DeleteMember(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := mocktrustycadb.NewMockOrgsDb(ctrl)
	svc := Service{
		db:          db,
		roleChecker: authctx.NewRoleChecker(db),
	}
	ctx := context.Background()

	adminMember := &model.MembershipInfo{
		ID:     xdb.NewID(10),
		OrgID:  xdb.NewID(1),
		UserID: xdb.NewID(7),
		Email:  "user@example.com",
		Role:   pb.Role_Admin,
	}
	ownerMember := &model.MembershipInfo{
		ID:     xdb.NewID(11),
		OrgID:  xdb.NewID(1),
		UserID: xdb.NewID(42),
		Email:  "owner@example.com",
		Role:   pb.Role_Owner,
	}

	_, err := svc.DeleteMember(ctx, &pb.DeleteMemberRequest{})
	require.Error(t, err)
	assert.EqualError(t, err, "bad_request: invalid org ID")

	_, err = svc.DeleteMember(ctx, &pb.DeleteMemberRequest{OrgID: "1"})
	require.Error(t, err)
	assert.EqualError(t, err, "bad_request: invalid user ID")

	db.EXPECT().ListMemberships(gomock.Any(), gomock.Any()).Return(nil, errors.New("db failed"))
	_, err = svc.DeleteMember(ctx, &pb.DeleteMemberRequest{OrgID: "1", UserID: "7"})
	require.Error(t, err)
	assert.EqualError(t, err, "unexpected: request failed")

	db.EXPECT().ListMemberships(gomock.Any(), gomock.Any()).Return(model.MembershipInfoSlice{adminMember}, nil)
	_, err = svc.DeleteMember(ctx, &pb.DeleteMemberRequest{OrgID: "1", UserID: "99"})
	require.Error(t, err)
	assert.EqualError(t, err, "unexpected: unable to find user")

	db.EXPECT().ListMemberships(gomock.Any(), gomock.Any()).Return(model.MembershipInfoSlice{ownerMember}, nil)
	_, err = svc.DeleteMember(ctx, &pb.DeleteMemberRequest{OrgID: "1", UserID: "42"})
	require.Error(t, err)
	assert.EqualError(t, err, "unauthorized: forbidden to delete owner")

	db.EXPECT().ListMemberships(gomock.Any(), gomock.Any()).Return(model.MembershipInfoSlice{adminMember}, nil)
	db.EXPECT().DeleteMember(gomock.Any(), &query.DeleteMemberRequest{
		OrgID:  1,
		UserID: 7,
	}).Return(int64(0), errors.New("db failed"))
	_, err = svc.DeleteMember(ctx, &pb.DeleteMemberRequest{OrgID: "1", UserID: "7"})
	require.Error(t, err)
	assert.EqualError(t, err, "unexpected: request failed")

	db.EXPECT().ListMemberships(gomock.Any(), gomock.Any()).Return(model.MembershipInfoSlice{adminMember}, nil)
	db.EXPECT().DeleteMember(gomock.Any(), &query.DeleteMemberRequest{
		OrgID:  1,
		UserID: 7,
	}).Return(int64(1), nil)
	res, err := svc.DeleteMember(ctx, &pb.DeleteMemberRequest{OrgID: "1", UserID: "7"})
	require.NoError(t, err)
	require.NotNil(t, res)
}

func TestService_DeleteInvite(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := mocktrustycadb.NewMockOrgsDb(ctrl)
	svc := Service{
		db:          db,
		roleChecker: authctx.NewRoleChecker(db),
	}
	ctx := context.Background()

	_, err := svc.DeleteInvite(ctx, &pb.DeleteInviteRequest{})
	require.Error(t, err)
	assert.EqualError(t, err, "bad_request: invalid org ID")

	db.EXPECT().DeleteInvite(gomock.Any(), &query.DeleteInviteRequest{
		OrgID: 1,
		Email: "invitee@example.com",
	}).Return(int64(0), errors.New("db failed"))
	_, err = svc.DeleteInvite(ctx, &pb.DeleteInviteRequest{
		OrgID: "1",
		Email: "invitee@example.com",
	})
	require.Error(t, err)
	assert.EqualError(t, err, "unexpected: request failed")

	db.EXPECT().DeleteInvite(gomock.Any(), &query.DeleteInviteRequest{
		OrgID: 1,
		Email: "invitee@example.com",
	}).Return(int64(1), nil)
	res, err := svc.DeleteInvite(ctx, &pb.DeleteInviteRequest{
		OrgID: "1",
		Email: "invitee@example.com",
	})
	require.NoError(t, err)
	require.NotNil(t, res)
}
