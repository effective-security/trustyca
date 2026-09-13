package orgs

import (
	"database/sql"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/mocks/mocktrustycadb"
	"github.com/effective-security/xdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestService_GetUserOrgs(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := mocktrustycadb.NewMockOrgsDb(ctrl)
	svc := Service{db: db, authorizer: newFakeAuthorizer()}

	// user 42: Admin in org 1, project-only in org 2
	rows := model.MembershipInfoSlice{
		{ID: xdb.NewID(10), OrgID: xdb.NewID(1), OrgAlias: "a1", OrgName: "Org 1", UserID: xdb.NewID(42), Role: pb.Role_Admin},
		{ID: xdb.NewID(11), OrgID: xdb.NewID(1), ProjectID: xdb.NewID(201), UserID: xdb.NewID(42), Role: pb.Role_Viewer},
		{ID: xdb.NewID(12), OrgID: xdb.NewID(2), OrgAlias: "a2", OrgName: "Org 2", ProjectID: xdb.NewID(301), UserID: xdb.NewID(42), Role: pb.Role_Admin},
	}
	db.EXPECT().GetUserMemberships(gomock.Any(), uint64(42)).Return(rows, nil)

	res, err := svc.GetUserOrgs(testCtx("42", ""), &emptypb.Empty{})
	require.NoError(t, err)
	require.Len(t, res.Orgs, 2)
	assert.Equal(t, "1", res.Orgs[0].OrgID)
	assert.Equal(t, "Org 1", res.Orgs[0].OrgName)
	assert.Equal(t, pb.Role_Admin, res.Orgs[0].Role)
	assert.Equal(t, pb.RoleSource_Direct, res.Orgs[0].RoleSource)
	assert.Equal(t, pb.Role_Admin, res.Orgs[0].ExplicitRole)
	assert.Equal(t, "2", res.Orgs[1].OrgID)
	assert.Equal(t, pb.Role_Viewer, res.Orgs[1].Role, "derived Viewer from project grant")
	assert.Equal(t, pb.RoleSource_Project, res.Orgs[1].RoleSource)
	assert.Equal(t, pb.Role_None, res.Orgs[1].ExplicitRole)

	_, err = svc.GetUserOrgs(testCtx("", ""), &emptypb.Empty{})
	assert.EqualError(t, err, "unauthorized: user is required")

	db.EXPECT().GetUserMemberships(gomock.Any(), uint64(42)).Return(nil, errors.New("db failed"))
	_, err = svc.GetUserOrgs(testCtx("42", ""), &emptypb.Empty{})
	assert.EqualError(t, err, "unexpected: failed to get memberships")
}

func TestService_GetUserMemberships(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := mocktrustycadb.NewMockOrgsDb(ctrl)
	svc := Service{db: db, authorizer: newFakeAuthorizer()}

	rows := model.MembershipInfoSlice{
		{ID: xdb.NewID(11), OrgID: xdb.NewID(1), OrgName: "Test Org", ProjectID: xdb.NewID(201), ProjectAlias: "payments", UserID: xdb.NewID(42), Role: pb.Role_Admin},
	}
	db.EXPECT().ListMemberships(gomock.Any(), &query.ListMembershipsRequest{OrgID: 1, UserID: 42, OrgStatus: pb.ItemStatus_Active}).Return(rows, nil)

	res, err := svc.GetUserMemberships(testCtx("42", "1"), &emptypb.Empty{})
	require.NoError(t, err)
	require.NotNil(t, res.Org)
	assert.Equal(t, pb.Role_Viewer, res.Org.Role)
	assert.Equal(t, pb.RoleSource_Project, res.Org.RoleSource)
	assert.Equal(t, "Test Org", res.Org.OrgName)
	require.Len(t, res.Memberships, 1)
	assert.Equal(t, pb.Scope_Project, res.Memberships[0].Scope)
	assert.Equal(t, "payments", res.Memberships[0].ProjectAlias)

	_, err = svc.GetUserMemberships(testCtx("42", ""), &emptypb.Empty{})
	assert.EqualError(t, err, "unauthorized: org not selected")

	db.EXPECT().ListMemberships(gomock.Any(), gomock.Any()).Return(nil, errors.New("db failed"))
	_, err = svc.GetUserMemberships(testCtx("42", "1"), &emptypb.Empty{})
	assert.EqualError(t, err, "unexpected: failed to get memberships")
}

func TestService_GetMembers(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := mocktrustycadb.NewMockOrgsDb(ctrl)
	// 42: org Admin; 7: Admin in project 201 only
	svc := Service{db: db, authorizer: newFakeAuthorizer(orgGrant(42, pb.Role_Admin), projectGrant(7, 201, pb.Role_Admin))}
	admin := testCtx("42", "1")
	projectAdmin := testCtx("7", "1")

	memberships := model.MembershipInfoSlice{orgGrant(42, pb.Role_Admin)}
	invites := model.InviteSlice{
		{ID: xdb.NewID(20), OrgID: xdb.NewID(1), InviterID: xdb.NewID(42), Email: "invitee@example.com", Role: pb.Role_User},
		{ID: xdb.NewID(21), OrgID: xdb.NewID(1), ProjectID: xdb.NewID(201), InviterID: xdb.NewID(42), Email: "p@example.com", Role: pb.Role_User},
	}

	// org-wide listing, all scopes
	db.EXPECT().ListMemberships(gomock.Any(), &query.ListMembershipsRequest{OrgID: 1}).Return(memberships, nil)
	db.EXPECT().GetOrgInvites(gomock.Any(), uint64(1)).Return(invites, nil)
	res, err := svc.GetMembers(admin, &pb.GetMembersRequest{})
	require.NoError(t, err)
	require.Len(t, res.Memberships, 1)
	require.Len(t, res.Invites, 2)

	// org scope only filters invites
	db.EXPECT().ListMemberships(gomock.Any(), &query.ListMembershipsRequest{OrgID: 1, Scope: pb.Scope_Org}).Return(memberships, nil)
	db.EXPECT().GetOrgInvites(gomock.Any(), uint64(1)).Return(invites, nil)
	res, err = svc.GetMembers(admin, &pb.GetMembersRequest{Scope: pb.Scope_Org})
	require.NoError(t, err)
	require.Len(t, res.Invites, 1)
	assert.Equal(t, "invitee@example.com", res.Invites[0].Email)

	// project listing by a project Admin
	db.EXPECT().ListMemberships(gomock.Any(), &query.ListMembershipsRequest{OrgID: 1, ProjectID: 201}).Return(model.MembershipInfoSlice{projectGrant(7, 201, pb.Role_Admin)}, nil)
	db.EXPECT().GetOrgInvites(gomock.Any(), uint64(1)).Return(invites, nil)
	res, err = svc.GetMembers(projectAdmin, &pb.GetMembersRequest{ProjectID: "201"})
	require.NoError(t, err)
	require.Len(t, res.Memberships, 1)
	require.Len(t, res.Invites, 1)
	assert.Equal(t, "201", res.Invites[0].ProjectID)

	_, err = svc.GetMembers(testCtx("42", ""), &pb.GetMembersRequest{})
	assert.EqualError(t, err, "unauthorized: org not selected")
	_, err = svc.GetMembers(admin, &pb.GetMembersRequest{ProjectID: "bad"})
	assert.EqualError(t, err, "bad_request: invalid project ID")

	db.EXPECT().ListMemberships(gomock.Any(), gomock.Any()).Return(nil, errors.New("db failed"))
	_, err = svc.GetMembers(admin, &pb.GetMembersRequest{})
	assert.EqualError(t, err, "unexpected: request failed")

	db.EXPECT().ListMemberships(gomock.Any(), gomock.Any()).Return(memberships, nil)
	db.EXPECT().GetOrgInvites(gomock.Any(), uint64(1)).Return(nil, errors.New("db failed"))
	_, err = svc.GetMembers(admin, &pb.GetMembersRequest{})
	assert.EqualError(t, err, "unexpected: request failed")
}

func TestService_AddMember(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := mocktrustycadb.NewMockOrgsDb(ctrl)
	db.EXPECT().TryCreateEvent(gomock.Any()).AnyTimes()
	// 42: Owner; 43: Admin; 7: project 201 Admin only; 8: org User
	az := newFakeAuthorizer(
		orgGrant(42, pb.Role_Owner),
		orgGrant(43, pb.Role_Admin),
		projectGrant(7, 201, pb.Role_Admin),
		orgGrant(8, pb.Role_User),
	)
	svc := Service{db: db, authorizer: az}
	owner := testCtx("42", "1")
	admin := testCtx("43", "1")
	projectAdmin := testCtx("7", "1")
	user := testCtx("8", "1")

	target := &model.User{ID: xdb.NewID(7), Email: "user@example.com", Name: "User Name"}
	newMember := &model.Membership{ID: xdb.NewID(10), OrgID: xdb.NewID(1), UserID: target.ID, Role: pb.Role_Admin, CreatedAt: xdb.ParseTime("2020-01-01")}

	// validation
	_, err := svc.AddMember(testCtx("42", ""), &pb.AddMemberRequest{Email: "a@b.c", Role: pb.Role_User})
	assert.EqualError(t, err, "unauthorized: org not selected")
	_, err = svc.AddMember(owner, &pb.AddMemberRequest{Role: pb.Role_User})
	assert.EqualError(t, err, "bad_request: email is required")
	_, err = svc.AddMember(owner, &pb.AddMemberRequest{Email: "a@b.c"})
	assert.EqualError(t, err, "bad_request: role is required")
	_, err = svc.AddMember(owner, &pb.AddMemberRequest{Email: "a@b.c", Role: pb.Role_User, ProjectID: "bad"})
	assert.EqualError(t, err, "bad_request: invalid project ID")

	// grantability
	_, err = svc.AddMember(admin, &pb.AddMemberRequest{Email: "a@b.c", Role: pb.Role_Owner})
	assert.EqualError(t, err, "unauthorized: not allowed to grant role Owner org-wide")
	_, err = svc.AddMember(user, &pb.AddMemberRequest{Email: "a@b.c", Role: pb.Role_Viewer})
	assert.EqualError(t, err, "unauthorized: not allowed to grant role Viewer org-wide")
	_, err = svc.AddMember(projectAdmin, &pb.AddMemberRequest{Email: "a@b.c", Role: pb.Role_Viewer})
	assert.EqualError(t, err, "unauthorized: not allowed to grant role Viewer org-wide", "project Admin cannot grant org-wide")
	_, err = svc.AddMember(projectAdmin, &pb.AddMemberRequest{Email: "a@b.c", Role: pb.Role_Viewer, ProjectID: "202"})
	assert.EqualError(t, err, "unauthorized: not allowed to grant role Viewer in the project", "no grant in project 202")
	_, err = svc.AddMember(owner, &pb.AddMemberRequest{Email: "a@b.c", Role: pb.Role_Owner, ProjectID: "201"})
	assert.EqualError(t, err, "unauthorized: not allowed to grant role Owner in the project", "Owner is not a project role")

	// org checks
	db.EXPECT().GetOrg(gomock.Any(), uint64(1)).Return(nil, errors.New("not found"))
	_, err = svc.AddMember(owner, &pb.AddMemberRequest{Email: "user@example.com", Role: pb.Role_Admin})
	assert.EqualError(t, err, "not_found: unable to find org")

	db.EXPECT().GetOrg(gomock.Any(), uint64(1)).Return(&model.Org{ID: xdb.NewID(1), Status: pb.ItemStatus_Inactive}, nil)
	_, err = svc.AddMember(owner, &pb.AddMemberRequest{Email: "user@example.com", Role: pb.Role_Admin})
	assert.EqualError(t, err, "unexpected: org is deleted")

	// project of another org
	db.EXPECT().GetOrg(gomock.Any(), uint64(1)).Return(testOrg, nil)
	_, err = svc.AddMember(owner, &pb.AddMemberRequest{Email: "user@example.com", Role: pb.Role_Admin, ProjectID: "301"})
	assert.EqualError(t, err, "not_found: project not found")

	// existing grant with the same role is returned as is
	existing := model.MembershipInfoSlice{{ID: xdb.NewID(11), OrgID: xdb.NewID(1), UserID: target.ID, Email: target.Email, Role: pb.Role_Admin}}
	db.EXPECT().GetOrg(gomock.Any(), uint64(1)).Return(testOrg, nil)
	db.EXPECT().GetUserByEmail(gomock.Any(), "user@example.com").Return(target, nil)
	db.EXPECT().ListMemberships(gomock.Any(), &query.ListMembershipsRequest{OrgID: 1, UserID: 7}).Return(existing, nil)
	res, err := svc.AddMember(owner, &pb.AddMemberRequest{Email: "  User@Example.com ", Role: pb.Role_Admin})
	require.NoError(t, err)
	assert.Equal(t, "11", res.Membership.ID)

	// existing grant with another role conflicts
	db.EXPECT().GetOrg(gomock.Any(), uint64(1)).Return(testOrg, nil)
	db.EXPECT().GetUserByEmail(gomock.Any(), "user@example.com").Return(target, nil)
	db.EXPECT().ListMemberships(gomock.Any(), gomock.Any()).Return(existing, nil)
	_, err = svc.AddMember(owner, &pb.AddMemberRequest{Email: "user@example.com", Role: pb.Role_User})
	assert.EqualError(t, err, "conflict: user already member")

	// a project grant is added next to an existing org-wide grant
	db.EXPECT().GetOrg(gomock.Any(), uint64(1)).Return(testOrg, nil)
	db.EXPECT().GetUserByEmail(gomock.Any(), "user@example.com").Return(target, nil)
	db.EXPECT().ListMemberships(gomock.Any(), gomock.Any()).Return(existing, nil)
	db.EXPECT().AddMember(gomock.Any(), gomock.Any()).DoAndReturn(func(_ any, m *model.Membership) (*model.Membership, error) {
		assert.Equal(t, uint64(201), m.ProjectID.UInt64())
		assert.Equal(t, pb.Role_Security, m.Role)
		return &model.Membership{ID: xdb.NewID(12), OrgID: xdb.NewID(1), ProjectID: xdb.NewID(201), UserID: target.ID, Role: pb.Role_Security}, nil
	})
	res, err = svc.AddMember(projectAdmin, &pb.AddMemberRequest{Email: "user@example.com", Role: pb.Role_Security, ProjectID: "201"})
	require.NoError(t, err)
	assert.Equal(t, "12", res.Membership.ID)
	assert.Equal(t, pb.Scope_Project, res.Membership.Scope)
	assert.Equal(t, "payments", res.Membership.ProjectAlias)
	assert.Equal(t, "Test Org", res.Membership.OrgName)
	assert.Contains(t, az.invalidated, "user:7")

	// org-wide grant by an Admin
	db.EXPECT().GetOrg(gomock.Any(), uint64(1)).Return(testOrg, nil)
	db.EXPECT().GetUserByEmail(gomock.Any(), "user@example.com").Return(target, nil)
	db.EXPECT().ListMemberships(gomock.Any(), gomock.Any()).Return(nil, nil)
	db.EXPECT().AddMember(gomock.Any(), gomock.Any()).Return(newMember, nil)
	res, err = svc.AddMember(admin, &pb.AddMemberRequest{Email: "user@example.com", Role: pb.Role_Admin})
	require.NoError(t, err)
	assert.Equal(t, "10", res.Membership.ID)
	assert.Equal(t, pb.Scope_Org, res.Membership.Scope)
	assert.Equal(t, "user@example.com", res.Membership.Email)

	db.EXPECT().GetOrg(gomock.Any(), uint64(1)).Return(testOrg, nil)
	db.EXPECT().GetUserByEmail(gomock.Any(), "user@example.com").Return(target, nil)
	db.EXPECT().ListMemberships(gomock.Any(), gomock.Any()).Return(nil, errors.New("db failed"))
	_, err = svc.AddMember(owner, &pb.AddMemberRequest{Email: "user@example.com", Role: pb.Role_Admin})
	assert.EqualError(t, err, "unexpected: request failed")

	db.EXPECT().GetOrg(gomock.Any(), uint64(1)).Return(testOrg, nil)
	db.EXPECT().GetUserByEmail(gomock.Any(), "user@example.com").Return(target, nil)
	db.EXPECT().ListMemberships(gomock.Any(), gomock.Any()).Return(nil, nil)
	db.EXPECT().AddMember(gomock.Any(), gomock.Any()).Return(nil, errors.New("db failed"))
	_, err = svc.AddMember(owner, &pb.AddMemberRequest{Email: "user@example.com", Role: pb.Role_Admin})
	assert.EqualError(t, err, "unexpected: request failed")

	// unknown user gets an invite at the requested scope
	invite := &model.Invite{ID: xdb.NewID(20), OrgID: xdb.NewID(1), ProjectID: xdb.NewID(201), InviterID: xdb.NewID(7), Email: "new@example.com", Role: pb.Role_User}
	db.EXPECT().GetOrg(gomock.Any(), uint64(1)).Return(testOrg, nil)
	db.EXPECT().GetUserByEmail(gomock.Any(), "new@example.com").Return(nil, sql.ErrNoRows)
	db.EXPECT().CreateInvite(gomock.Any(), gomock.Any()).DoAndReturn(func(_ any, inv *model.Invite) (*model.Invite, error) {
		assert.Equal(t, uint64(201), inv.ProjectID.UInt64())
		assert.Equal(t, uint64(7), inv.InviterID.UInt64())
		return invite, nil
	})
	res, err = svc.AddMember(projectAdmin, &pb.AddMemberRequest{Email: "new@example.com", Role: pb.Role_User, ProjectID: "201"})
	require.NoError(t, err)
	require.NotNil(t, res.Invite)
	assert.Equal(t, "20", res.Invite.ID)
	assert.Equal(t, pb.Scope_Project, res.Invite.Scope)
	assert.Nil(t, res.Membership)

	db.EXPECT().GetOrg(gomock.Any(), uint64(1)).Return(testOrg, nil)
	db.EXPECT().GetUserByEmail(gomock.Any(), "new@example.com").Return(nil, errors.New("connection failed"))
	db.EXPECT().CreateInvite(gomock.Any(), gomock.Any()).Return(nil, errors.New("db failed"))
	_, err = svc.AddMember(owner, &pb.AddMemberRequest{Email: "new@example.com", Role: pb.Role_User})
	assert.EqualError(t, err, "unexpected: request failed")
}

func TestService_ChangeMemberRole(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := mocktrustycadb.NewMockOrgsDb(ctrl)
	db.EXPECT().TryCreateEvent(gomock.Any()).AnyTimes()
	az := newFakeAuthorizer(orgGrant(42, pb.Role_Owner), orgGrant(43, pb.Role_Admin), projectGrant(7, 201, pb.Role_Admin))
	svc := Service{db: db, authorizer: az}
	owner := testCtx("42", "1")
	admin := testCtx("43", "1")
	projectAdmin := testCtx("7", "1")

	target := &model.User{ID: xdb.NewID(9), Email: "user@example.com", Name: "User Name"}
	adminMember := &model.MembershipInfo{ID: xdb.NewID(10), OrgID: xdb.NewID(1), UserID: target.ID, Email: target.Email, Role: pb.Role_Admin}
	ownerMember := &model.MembershipInfo{ID: xdb.NewID(11), OrgID: xdb.NewID(1), UserID: xdb.NewID(42), Email: "owner@example.com", Role: pb.Role_Owner}
	orgScope := &query.ListMembershipsRequest{OrgID: 1, Scope: pb.Scope_Org}

	_, err := svc.ChangeMemberRole(testCtx("42", ""), &pb.ChangeMemberRoleRequest{UserID: "9", Role: pb.Role_User})
	assert.EqualError(t, err, "unauthorized: org not selected")
	_, err = svc.ChangeMemberRole(owner, &pb.ChangeMemberRoleRequest{UserID: "9"})
	assert.EqualError(t, err, "bad_request: role is required")
	_, err = svc.ChangeMemberRole(admin, &pb.ChangeMemberRoleRequest{UserID: "9", Role: pb.Role_Owner})
	assert.EqualError(t, err, "unauthorized: not allowed to grant role Owner org-wide")

	db.EXPECT().ListMemberships(gomock.Any(), orgScope).Return(nil, errors.New("db failed"))
	_, err = svc.ChangeMemberRole(owner, &pb.ChangeMemberRoleRequest{UserID: "9", Role: pb.Role_User})
	assert.EqualError(t, err, "unexpected: request failed")

	db.EXPECT().ListMemberships(gomock.Any(), orgScope).Return(model.MembershipInfoSlice{adminMember}, nil)
	_, err = svc.ChangeMemberRole(owner, &pb.ChangeMemberRoleRequest{UserID: "bad", Role: pb.Role_User})
	assert.EqualError(t, err, "bad_request: invalid user ID")

	db.EXPECT().ListMemberships(gomock.Any(), orgScope).Return(model.MembershipInfoSlice{adminMember}, nil)
	_, err = svc.ChangeMemberRole(owner, &pb.ChangeMemberRoleRequest{Role: pb.Role_User})
	assert.EqualError(t, err, "bad_request: user ID or email is required")

	db.EXPECT().ListMemberships(gomock.Any(), orgScope).Return(model.MembershipInfoSlice{adminMember}, nil)
	_, err = svc.ChangeMemberRole(owner, &pb.ChangeMemberRoleRequest{UserID: "99", Role: pb.Role_User})
	assert.EqualError(t, err, "not_found: unable to find member")

	// an Admin cannot demote an Owner: revoking requires granting the current role
	db.EXPECT().ListMemberships(gomock.Any(), orgScope).Return(model.MembershipInfoSlice{ownerMember}, nil)
	_, err = svc.ChangeMemberRole(admin, &pb.ChangeMemberRoleRequest{UserID: "42", Role: pb.Role_Admin})
	assert.EqualError(t, err, "unauthorized: not allowed to grant role Owner org-wide")

	// the last Owner cannot be demoted
	db.EXPECT().ListMemberships(gomock.Any(), orgScope).Return(model.MembershipInfoSlice{ownerMember}, nil)
	db.EXPECT().ListMemberships(gomock.Any(), &query.ListMembershipsRequest{OrgID: 1, Scope: pb.Scope_Org, Role: pb.Role_Owner}).Return(model.MembershipInfoSlice{ownerMember}, nil)
	_, err = svc.ChangeMemberRole(owner, &pb.ChangeMemberRoleRequest{UserID: "42", Role: pb.Role_Admin})
	assert.EqualError(t, err, "unexpected: the org must keep at least one owner")

	// same role is a no-op
	db.EXPECT().ListMemberships(gomock.Any(), orgScope).Return(model.MembershipInfoSlice{adminMember}, nil)
	res, err := svc.ChangeMemberRole(owner, &pb.ChangeMemberRoleRequest{Email: "User@example.com", Role: pb.Role_Admin})
	require.NoError(t, err)
	assert.Equal(t, "10", res.ID)

	db.EXPECT().ListMemberships(gomock.Any(), orgScope).Return(model.MembershipInfoSlice{adminMember}, nil)
	db.EXPECT().GetOrg(gomock.Any(), uint64(1)).Return(nil, errors.New("not found"))
	_, err = svc.ChangeMemberRole(owner, &pb.ChangeMemberRoleRequest{UserID: "9", Role: pb.Role_User})
	assert.EqualError(t, err, "not_found: unable to find org")

	db.EXPECT().ListMemberships(gomock.Any(), orgScope).Return(model.MembershipInfoSlice{adminMember}, nil)
	db.EXPECT().GetOrg(gomock.Any(), uint64(1)).Return(testOrg, nil)
	db.EXPECT().GetUser(gomock.Any(), uint64(9)).Return(nil, errors.New("not found"))
	_, err = svc.ChangeMemberRole(owner, &pb.ChangeMemberRoleRequest{UserID: "9", Role: pb.Role_User})
	assert.EqualError(t, err, "not_found: unable to find user")

	db.EXPECT().ListMemberships(gomock.Any(), orgScope).Return(model.MembershipInfoSlice{adminMember}, nil)
	db.EXPECT().GetOrg(gomock.Any(), uint64(1)).Return(testOrg, nil)
	db.EXPECT().GetUser(gomock.Any(), uint64(9)).Return(target, nil)
	db.EXPECT().UpdateMemberRole(gomock.Any(), &query.UpdateMemberRoleRequest{OrgID: 1, UserID: 9, Role: pb.Role_User}).Return(nil, errors.New("db failed"))
	_, err = svc.ChangeMemberRole(owner, &pb.ChangeMemberRoleRequest{UserID: "9", Role: pb.Role_User})
	assert.EqualError(t, err, "unexpected: request failed")

	db.EXPECT().ListMemberships(gomock.Any(), orgScope).Return(model.MembershipInfoSlice{adminMember}, nil)
	db.EXPECT().GetOrg(gomock.Any(), uint64(1)).Return(testOrg, nil)
	db.EXPECT().GetUser(gomock.Any(), uint64(9)).Return(target, nil)
	db.EXPECT().UpdateMemberRole(gomock.Any(), &query.UpdateMemberRoleRequest{OrgID: 1, UserID: 9, Role: pb.Role_User}).Return(&model.Membership{
		ID: adminMember.ID, OrgID: xdb.NewID(1), UserID: target.ID, Role: pb.Role_User,
	}, nil)
	res, err = svc.ChangeMemberRole(admin, &pb.ChangeMemberRoleRequest{UserID: "9", Role: pb.Role_User})
	require.NoError(t, err)
	assert.Equal(t, pb.Role_User, res.Role)
	assert.Equal(t, "Test Org", res.OrgName)
	assert.Contains(t, az.invalidated, "user:9")

	// project scope by a project Admin
	projectScope := &query.ListMembershipsRequest{OrgID: 1, ProjectID: 201, Scope: pb.Scope_Project}
	projectMember := &model.MembershipInfo{ID: xdb.NewID(12), OrgID: xdb.NewID(1), ProjectID: xdb.NewID(201), UserID: target.ID, Email: target.Email, Role: pb.Role_Viewer}
	db.EXPECT().ListMemberships(gomock.Any(), projectScope).Return(model.MembershipInfoSlice{projectMember}, nil)
	db.EXPECT().GetOrg(gomock.Any(), uint64(1)).Return(testOrg, nil)
	db.EXPECT().GetUser(gomock.Any(), uint64(9)).Return(target, nil)
	db.EXPECT().UpdateMemberRole(gomock.Any(), &query.UpdateMemberRoleRequest{OrgID: 1, ProjectID: 201, UserID: 9, Role: pb.Role_User}).Return(&model.Membership{
		ID: projectMember.ID, OrgID: xdb.NewID(1), ProjectID: xdb.NewID(201), UserID: target.ID, Role: pb.Role_User,
	}, nil)
	res, err = svc.ChangeMemberRole(projectAdmin, &pb.ChangeMemberRoleRequest{UserID: "9", Role: pb.Role_User, ProjectID: "201"})
	require.NoError(t, err)
	assert.Equal(t, pb.Scope_Project, res.Scope)
	assert.Equal(t, "payments", res.ProjectAlias)

	_, err = svc.ChangeMemberRole(projectAdmin, &pb.ChangeMemberRoleRequest{UserID: "9", Role: pb.Role_User, ProjectID: "202"})
	assert.EqualError(t, err, "unauthorized: not allowed to grant role User in the project")
}

func TestService_DeleteMember(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := mocktrustycadb.NewMockOrgsDb(ctrl)
	db.EXPECT().TryCreateEvent(gomock.Any()).AnyTimes()
	az := newFakeAuthorizer(orgGrant(42, pb.Role_Owner), orgGrant(43, pb.Role_Admin), projectGrant(7, 201, pb.Role_Admin))
	svc := Service{db: db, authorizer: az}
	owner := testCtx("42", "1")
	admin := testCtx("43", "1")
	projectAdmin := testCtx("7", "1")
	orgScope := &query.ListMembershipsRequest{OrgID: 1, Scope: pb.Scope_Org}

	adminMember := &model.MembershipInfo{ID: xdb.NewID(10), OrgID: xdb.NewID(1), UserID: xdb.NewID(9), Email: "user@example.com", Role: pb.Role_Admin}
	ownerMember := &model.MembershipInfo{ID: xdb.NewID(11), OrgID: xdb.NewID(1), UserID: xdb.NewID(42), Email: "owner@example.com", Role: pb.Role_Owner}
	secondOwner := &model.MembershipInfo{ID: xdb.NewID(13), OrgID: xdb.NewID(1), UserID: xdb.NewID(44), Email: "owner2@example.com", Role: pb.Role_Owner}

	_, err := svc.DeleteMember(testCtx("42", ""), &pb.DeleteMemberRequest{UserID: "9"})
	assert.EqualError(t, err, "unauthorized: org not selected")
	_, err = svc.DeleteMember(owner, &pb.DeleteMemberRequest{})
	assert.EqualError(t, err, "bad_request: invalid user ID")

	db.EXPECT().ListMemberships(gomock.Any(), orgScope).Return(nil, errors.New("db failed"))
	_, err = svc.DeleteMember(owner, &pb.DeleteMemberRequest{UserID: "9"})
	assert.EqualError(t, err, "unexpected: request failed")

	db.EXPECT().ListMemberships(gomock.Any(), orgScope).Return(model.MembershipInfoSlice{adminMember}, nil)
	_, err = svc.DeleteMember(owner, &pb.DeleteMemberRequest{UserID: "99"})
	assert.EqualError(t, err, "not_found: unable to find member")

	// an Admin cannot remove an Owner
	db.EXPECT().ListMemberships(gomock.Any(), orgScope).Return(model.MembershipInfoSlice{ownerMember}, nil)
	_, err = svc.DeleteMember(admin, &pb.DeleteMemberRequest{UserID: "42"})
	assert.EqualError(t, err, "unauthorized: not allowed to grant role Owner org-wide")

	// the last Owner cannot be removed
	db.EXPECT().ListMemberships(gomock.Any(), orgScope).Return(model.MembershipInfoSlice{ownerMember}, nil)
	db.EXPECT().ListMemberships(gomock.Any(), &query.ListMembershipsRequest{OrgID: 1, Scope: pb.Scope_Org, Role: pb.Role_Owner}).Return(model.MembershipInfoSlice{ownerMember}, nil)
	_, err = svc.DeleteMember(owner, &pb.DeleteMemberRequest{UserID: "42"})
	assert.EqualError(t, err, "unexpected: the org must keep at least one owner")

	// an Owner can be removed when another Owner remains
	db.EXPECT().ListMemberships(gomock.Any(), orgScope).Return(model.MembershipInfoSlice{ownerMember, secondOwner}, nil)
	db.EXPECT().ListMemberships(gomock.Any(), &query.ListMembershipsRequest{OrgID: 1, Scope: pb.Scope_Org, Role: pb.Role_Owner}).Return(model.MembershipInfoSlice{ownerMember, secondOwner}, nil)
	db.EXPECT().DeleteMember(gomock.Any(), &query.DeleteMemberRequest{OrgID: 1, UserID: 44, Scope: pb.Scope_Org}).Return(int64(1), nil)
	_, err = svc.DeleteMember(owner, &pb.DeleteMemberRequest{UserID: "44"})
	require.NoError(t, err)

	db.EXPECT().ListMemberships(gomock.Any(), orgScope).Return(model.MembershipInfoSlice{adminMember}, nil)
	db.EXPECT().DeleteMember(gomock.Any(), &query.DeleteMemberRequest{OrgID: 1, UserID: 9, Scope: pb.Scope_Org}).Return(int64(0), errors.New("db failed"))
	_, err = svc.DeleteMember(admin, &pb.DeleteMemberRequest{UserID: "9"})
	assert.EqualError(t, err, "unexpected: request failed")

	db.EXPECT().ListMemberships(gomock.Any(), orgScope).Return(model.MembershipInfoSlice{adminMember}, nil)
	db.EXPECT().DeleteMember(gomock.Any(), &query.DeleteMemberRequest{OrgID: 1, UserID: 9, Scope: pb.Scope_Org}).Return(int64(1), nil)
	_, err = svc.DeleteMember(admin, &pb.DeleteMemberRequest{UserID: "9"})
	require.NoError(t, err)
	assert.Contains(t, az.invalidated, "user:9")

	// project grant removed by a project Admin; the org-wide grant is untouched
	projectMember := &model.MembershipInfo{ID: xdb.NewID(12), OrgID: xdb.NewID(1), ProjectID: xdb.NewID(201), UserID: xdb.NewID(9), Role: pb.Role_User}
	db.EXPECT().ListMemberships(gomock.Any(), &query.ListMembershipsRequest{OrgID: 1, ProjectID: 201, Scope: pb.Scope_Project}).Return(model.MembershipInfoSlice{projectMember}, nil)
	db.EXPECT().DeleteMember(gomock.Any(), &query.DeleteMemberRequest{OrgID: 1, ProjectID: 201, UserID: 9, Scope: pb.Scope_Project}).Return(int64(1), nil)
	_, err = svc.DeleteMember(projectAdmin, &pb.DeleteMemberRequest{UserID: "9", ProjectID: "201"})
	require.NoError(t, err)

	// a project Admin cannot remove an org-wide grant
	db.EXPECT().ListMemberships(gomock.Any(), orgScope).Return(model.MembershipInfoSlice{adminMember}, nil)
	_, err = svc.DeleteMember(projectAdmin, &pb.DeleteMemberRequest{UserID: "9"})
	assert.EqualError(t, err, "unauthorized: not allowed to grant role Admin org-wide")
}

func TestService_DeleteInvite(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := mocktrustycadb.NewMockOrgsDb(ctrl)
	svc := Service{db: db, authorizer: newFakeAuthorizer(orgGrant(42, pb.Role_Admin))}
	ctx := testCtx("42", "1")

	_, err := svc.DeleteInvite(testCtx("42", ""), &pb.DeleteInviteRequest{Email: "a@b.c"})
	assert.EqualError(t, err, "unauthorized: org not selected")
	_, err = svc.DeleteInvite(ctx, &pb.DeleteInviteRequest{})
	assert.EqualError(t, err, "bad_request: email is required")
	_, err = svc.DeleteInvite(ctx, &pb.DeleteInviteRequest{Email: "a@b.c", ProjectID: "bad"})
	assert.EqualError(t, err, "bad_request: invalid project ID")

	db.EXPECT().DeleteInvite(gomock.Any(), &query.DeleteInviteRequest{OrgID: 1, Email: "invitee@example.com", Scope: pb.Scope_Org}).Return(int64(0), errors.New("db failed"))
	_, err = svc.DeleteInvite(ctx, &pb.DeleteInviteRequest{Email: "invitee@example.com"})
	assert.EqualError(t, err, "unexpected: request failed")

	db.EXPECT().DeleteInvite(gomock.Any(), &query.DeleteInviteRequest{OrgID: 1, Email: "invitee@example.com", Scope: pb.Scope_Org}).Return(int64(1), nil)
	res, err := svc.DeleteInvite(ctx, &pb.DeleteInviteRequest{Email: " Invitee@example.com "})
	require.NoError(t, err)
	require.NotNil(t, res)

	db.EXPECT().DeleteInvite(gomock.Any(), &query.DeleteInviteRequest{OrgID: 1, ProjectID: 201, Email: "invitee@example.com", Scope: pb.Scope_Project}).Return(int64(1), nil)
	_, err = svc.DeleteInvite(ctx, &pb.DeleteInviteRequest{Email: "invitee@example.com", ProjectID: "201"})
	require.NoError(t, err)
}
