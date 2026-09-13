package pgsql_test

import (
	"testing"
	"time"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/xdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Member(t *testing.T) {
	userID := provider.NextID()
	login := &model.Login{
		ID:         userID,
		ExternalID: userID.String(),
		Name:       "Test Member User",
		Email:      userID.String() + "@example.com",
		Provider:   pb.IDP_Github,
	}
	_, user, err := provider.LoginUser(ctx, login)
	require.NoError(t, err)
	defer func() {
		_, err := provider.DeleteUserByEmail(ctx, login.Email)
		assert.NoError(t, err)
	}()

	org := &model.Org{
		Name: "Test Member Org",
	}
	org, err = provider.RegisterOrg(ctx, org, user.ID.UInt64())
	require.NoError(t, err)
	defer func() {
		_, err := provider.DeleteOrg(ctx, org.ID.UInt64())
		assert.NoError(t, err)
	}()

	memberships, err := provider.ListMemberships(ctx, &query.ListMembershipsRequest{UserID: user.ID.UInt64()})
	require.NoError(t, err)
	require.Equal(t, 1, len(memberships))
	assert.Equal(t, org.ID.UInt64(), memberships[0].OrgID.UInt64())
	assert.Equal(t, pb.Role_Owner, memberships[0].Role)
	assert.Equal(t, pb.Scope_Org, memberships[0].Scope())
	assert.Empty(t, memberships[0].ProjectAlias)

	updated, err := provider.UpdateMemberRole(ctx, &query.UpdateMemberRoleRequest{
		OrgID:  org.ID.UInt64(),
		UserID: user.ID.UInt64(),
		Role:   pb.Role_Admin,
	})
	require.NoError(t, err)
	assert.Equal(t, pb.Role_Admin, updated.Role)

	count, err := provider.DeleteMember(ctx, &query.DeleteMemberRequest{
		OrgID:  org.ID.UInt64(),
		UserID: user.ID.UInt64(),
		Scope:  pb.Scope_Org,
	})
	require.NoError(t, err)
	assert.EqualValues(t, 1, count)

	memberships, err = provider.ListMemberships(ctx, &query.ListMembershipsRequest{OrgID: org.ID.UInt64()})
	require.NoError(t, err)
	assert.Empty(t, memberships)
}

func Test_ProjectMembership(t *testing.T) {
	owner, org := setupOwnerAndOrg(t, "Test_ProjectMembership")

	// second org to check project isolation
	_, otherOrg := setupOwnerAndOrg(t, "Test_ProjectMembership_Other")

	project1, err := provider.RegisterProject(ctx, &model.Project{
		OrgID: org.ID,
		Alias: "project-1-" + org.ID.String(),
		Name:  "Project 1",
	})
	require.NoError(t, err)
	assert.Equal(t, pb.ItemStatus_Active, project1.Status)

	project2, err := provider.RegisterProject(ctx, &model.Project{
		OrgID: org.ID,
		Name:  "Project 2",
	})
	require.NoError(t, err)
	assert.True(t, len(project2.Alias) > len(model.ProjectAliasPrefix), "alias must be generated")

	// alias is unique per org
	_, err = provider.RegisterProject(ctx, &model.Project{OrgID: org.ID, Alias: project1.Alias, Name: "Duplicate"})
	require.Error(t, err)

	// but the same alias is allowed in another org
	otherProject, err := provider.RegisterProject(ctx, &model.Project{OrgID: otherOrg.ID, Alias: project1.Alias, Name: "Other org project"})
	require.NoError(t, err)

	got, err := provider.GetProject(ctx, project1.ID.UInt64())
	require.NoError(t, err)
	assert.Equal(t, project1.Alias, got.Alias)

	found, err := provider.FindProject(ctx, org.ID.UInt64(), project1.Alias)
	require.NoError(t, err)
	assert.Equal(t, project1.ID.UInt64(), found.ID.UInt64())

	_, err = provider.FindProject(ctx, org.ID.UInt64(), "no-such-alias")
	assert.ErrorContains(t, err, "record not found")

	list, err := provider.ListProjects(ctx, &query.ListProjectsRequest{OrgID: org.ID.UInt64(), Limit: 10})
	require.NoError(t, err)
	require.Len(t, list.Rows, 2)
	assert.False(t, list.HasNextPage)

	// only the granted projects
	list, err = provider.ListProjects(ctx, &query.ListProjectsRequest{OrgID: org.ID.UInt64(), IDs: []uint64{project2.ID.UInt64()}, Limit: 10})
	require.NoError(t, err)
	require.Len(t, list.Rows, 1)
	assert.Equal(t, project2.ID, list.Rows[0].ID)

	updatedProject, err := provider.UpdateProject(ctx, &query.UpdateProjectRequest{ID: project2.ID.UInt64(), Name: "Project 2 renamed", Description: "desc"})
	require.NoError(t, err)
	assert.Equal(t, "Project 2 renamed", updatedProject.Name)
	assert.Equal(t, "desc", string(updatedProject.Description))

	_, err = provider.UpdateProject(ctx, &query.UpdateProjectRequest{ID: project2.ID.UInt64()})
	assert.EqualError(t, err, "no changes to update")

	// member: org-wide User, Admin in project1
	memberID := provider.NextID()
	memberLogin := &model.Login{
		ID:         memberID,
		ExternalID: memberID.String(),
		Name:       "Project Member",
		Email:      memberID.String() + "@example.com",
		Provider:   pb.IDP_Github,
	}
	_, member, err := provider.LoginUser(ctx, memberLogin)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := provider.DeleteUserByEmail(ctx, memberLogin.Email)
		assert.NoError(t, err)
	})

	orgGrant, err := provider.AddMember(ctx, &model.Membership{OrgID: org.ID, UserID: member.ID, Role: pb.Role_User})
	require.NoError(t, err)
	assert.Equal(t, pb.Scope_Org, orgGrant.Scope())

	projectGrant, err := provider.AddMember(ctx, &model.Membership{OrgID: org.ID, ProjectID: project1.ID, UserID: member.ID, Role: pb.Role_Admin})
	require.NoError(t, err)
	assert.Equal(t, pb.Scope_Project, projectGrant.Scope())
	assert.NotEqual(t, orgGrant.ID.UInt64(), projectGrant.ID.UInt64())

	// re-adding at the same scope updates the role
	projectGrant2, err := provider.AddMember(ctx, &model.Membership{OrgID: org.ID, ProjectID: project1.ID, UserID: member.ID, Role: pb.Role_Support})
	require.NoError(t, err)
	assert.Equal(t, projectGrant.ID.UInt64(), projectGrant2.ID.UInt64())
	assert.Equal(t, pb.Role_Support, projectGrant2.Role)

	// the composite FK rejects a project of another org
	_, err = provider.AddMember(ctx, &model.Membership{OrgID: org.ID, ProjectID: otherProject.ID, UserID: member.ID, Role: pb.Role_User})
	require.Error(t, err, "project must belong to the membership org")

	// all scopes for the user: 2 rows
	all, err := provider.ListMemberships(ctx, &query.ListMembershipsRequest{OrgID: org.ID.UInt64(), UserID: member.ID.UInt64()})
	require.NoError(t, err)
	require.Len(t, all, 2)

	// org-wide only: owner + member
	orgOnly, err := provider.ListMemberships(ctx, &query.ListMembershipsRequest{OrgID: org.ID.UInt64(), Scope: pb.Scope_Org})
	require.NoError(t, err)
	require.Len(t, orgOnly, 2)
	for _, m := range orgOnly {
		assert.Equal(t, pb.Scope_Org, m.Scope())
	}

	// project1 only
	projectOnly, err := provider.ListMemberships(ctx, &query.ListMembershipsRequest{OrgID: org.ID.UInt64(), ProjectID: project1.ID.UInt64()})
	require.NoError(t, err)
	require.Len(t, projectOnly, 1)
	assert.Equal(t, member.ID, projectOnly[0].UserID)
	assert.Equal(t, project1.Alias, projectOnly[0].ProjectAlias)
	assert.Equal(t, "Project 1", projectOnly[0].ProjectName)
	assert.Equal(t, pb.Role_Support, projectOnly[0].Role)

	// any project scope
	anyProject, err := provider.ListMemberships(ctx, &query.ListMembershipsRequest{OrgID: org.ID.UInt64(), Scope: pb.Scope_Project})
	require.NoError(t, err)
	require.Len(t, anyProject, 1)

	// grants are plain rows: one org-wide User row and one project Support row
	var orgRole, projectRole pb.Role_Enum
	for _, m := range all {
		switch m.ProjectID.UInt64() {
		case 0:
			orgRole = m.Role
		case project1.ID.UInt64():
			projectRole = m.Role
		}
	}
	assert.Equal(t, pb.Role_User, orgRole)
	assert.Equal(t, pb.Role_Support, projectRole)

	// the user's orgs are returned once each
	userOrgs, err := provider.GetUserOrgs(ctx, member.ID.UInt64())
	require.NoError(t, err)
	require.Len(t, userOrgs, 1)
	assert.Equal(t, org.ID.UInt64(), userOrgs[0].ID.UInt64())

	userMemberships, err := provider.GetUserMemberships(ctx, member.ID.UInt64())
	require.NoError(t, err)
	require.Len(t, userMemberships, 2)

	// update the project grant only
	upd, err := provider.UpdateMemberRole(ctx, &query.UpdateMemberRoleRequest{
		OrgID: org.ID.UInt64(), ProjectID: project1.ID.UInt64(), UserID: member.ID.UInt64(), Role: pb.Role_Admin,
	})
	require.NoError(t, err)
	assert.Equal(t, projectGrant.ID.UInt64(), upd.ID.UInt64())
	assert.Equal(t, pb.Role_Admin, upd.Role)

	// no project grant in project2
	_, err = provider.UpdateMemberRole(ctx, &query.UpdateMemberRoleRequest{
		OrgID: org.ID.UInt64(), ProjectID: project2.ID.UInt64(), UserID: member.ID.UInt64(), Role: pb.Role_Admin,
	})
	assert.ErrorContains(t, err, "record not found")

	// project invite and acceptance
	inviteeID := provider.NextID()
	inviteeEmail := inviteeID.String() + "@example.com"
	projectInvite, err := provider.CreateInvite(ctx, &model.Invite{
		OrgID: org.ID, ProjectID: project1.ID, InviterID: owner.ID, Email: inviteeEmail, Role: pb.Role_User,
	})
	require.NoError(t, err)
	assert.Equal(t, pb.Scope_Project, projectInvite.Scope())
	assert.False(t, projectInvite.ExpiresAt.IsZero(), "default expiry is set")

	orgInvite, err := provider.CreateInvite(ctx, &model.Invite{
		OrgID: org.ID, InviterID: owner.ID, Email: inviteeEmail, Role: pb.Role_Billing,
	})
	require.NoError(t, err)
	assert.Equal(t, pb.Scope_Org, orgInvite.Scope())
	assert.NotEqual(t, projectInvite.ID.UInt64(), orgInvite.ID.UInt64())

	// an expired invite grants nothing
	expiredEmail := provider.NextID().String() + "@example.com"
	expired, err := provider.CreateInvite(ctx, &model.Invite{
		OrgID: org.ID, InviterID: owner.ID, Email: expiredEmail, Role: pb.Role_User,
		ExpiresAt: xdb.Time(time.Now().Add(-time.Hour)),
	})
	require.NoError(t, err)
	pending, err := provider.GetUserInvites(ctx, expiredEmail)
	require.NoError(t, err)
	assert.Empty(t, pending, "expired invites are not pending")
	_, err = provider.DeleteInviteByID(ctx, expired.ID.UInt64())
	require.NoError(t, err)

	gotInvite, err := provider.GetInviteByOrgAndEmail(ctx, org.ID.UInt64(), project1.ID.UInt64(), inviteeEmail)
	require.NoError(t, err)
	assert.Equal(t, projectInvite.ID.UInt64(), gotInvite.ID.UInt64())
	gotInvite, err = provider.GetInviteByOrgAndEmail(ctx, org.ID.UInt64(), 0, inviteeEmail)
	require.NoError(t, err)
	assert.Equal(t, orgInvite.ID.UInt64(), gotInvite.ID.UInt64())

	invites, err := provider.GetOrgInvites(ctx, org.ID.UInt64())
	require.NoError(t, err)
	assert.Len(t, invites, 2)
	assert.Len(t, invites.FilterByProject(project1.ID.UInt64()), 1)
	assert.Len(t, invites.FilterByProject(0), 1)

	inviteeLogin := &model.Login{
		ID:         inviteeID,
		ExternalID: inviteeID.String(),
		Name:       "Invitee",
		Email:      inviteeEmail,
		Provider:   pb.IDP_Github,
	}
	_, invitee, err := provider.LoginUser(ctx, inviteeLogin)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := provider.DeleteUserByEmail(ctx, inviteeLogin.Email)
		assert.NoError(t, err)
	})

	accepted, err := provider.AcceptInvite(ctx, projectInvite.ID.UInt64(), invitee.ID.UInt64())
	require.NoError(t, err)
	assert.Equal(t, project1.ID.UInt64(), accepted.ProjectID.UInt64())
	assert.Equal(t, pb.Role_User, accepted.Role)

	n, err := provider.AcceptInvites(ctx, invitee)
	require.NoError(t, err)
	assert.EqualValues(t, 1, n)

	inviteeMemberships, err := provider.ListMemberships(ctx, &query.ListMembershipsRequest{OrgID: org.ID.UInt64(), UserID: invitee.ID.UInt64()})
	require.NoError(t, err)
	require.Len(t, inviteeMemberships, 2)
	inviteeRoles := map[uint64]pb.Role_Enum{}
	for _, m := range inviteeMemberships {
		inviteeRoles[m.ProjectID.UInt64()] = m.Role
	}
	assert.Equal(t, pb.Role_Billing, inviteeRoles[0], "org-wide grant")
	assert.Equal(t, pb.Role_User, inviteeRoles[project1.ID.UInt64()], "project grant")

	// invites are consumed by acceptance
	deleted, err := provider.DeleteInvite(ctx, &query.DeleteInviteRequest{OrgID: org.ID.UInt64(), Email: inviteeEmail, Scope: pb.Scope_Org})
	require.NoError(t, err)
	assert.EqualValues(t, 0, deleted)

	// delete the project grant only; the org-wide grant stays
	count, err := provider.DeleteMember(ctx, &query.DeleteMemberRequest{
		OrgID: org.ID.UInt64(), ProjectID: project1.ID.UInt64(), UserID: member.ID.UInt64(),
	})
	require.NoError(t, err)
	assert.EqualValues(t, 1, count)

	remaining, err := provider.ListMemberships(ctx, &query.ListMembershipsRequest{OrgID: org.ID.UInt64(), UserID: member.ID.UInt64()})
	require.NoError(t, err)
	require.Len(t, remaining, 1)
	assert.Equal(t, pb.Scope_Org, remaining[0].Scope())

	// deactivate project1: grants of the project are kept
	inactive, err := provider.UpdateProject(ctx, &query.UpdateProjectRequest{ID: project1.ID.UInt64(), Status: pb.ItemStatus_Inactive})
	require.NoError(t, err)
	assert.Equal(t, pb.ItemStatus_Inactive, inactive.Status)

	active, err := provider.ListProjects(ctx, &query.ListProjectsRequest{OrgID: org.ID.UInt64(), Status: pb.ItemStatus_Active, Limit: 10})
	require.NoError(t, err)
	require.Len(t, active.Rows, 1)
	assert.Equal(t, project2.ID, active.Rows[0].ID)

	// the other org still has its project
	_, err = provider.GetProject(ctx, otherProject.ID.UInt64())
	require.NoError(t, err)
}

func Test_UpdateMemberRole_NotFound(t *testing.T) {
	_, err := provider.UpdateMemberRole(ctx, &query.UpdateMemberRoleRequest{OrgID: 123, UserID: 456, Role: pb.Role_Admin})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "record not found")

	_, err = provider.UpdateMemberRole(ctx, &query.UpdateMemberRoleRequest{OrgID: 123})
	assert.EqualError(t, err, "orgID, userID and role are required")
}

func Test_DeleteMember_InvalidRequest(t *testing.T) {
	_, err := provider.DeleteMember(ctx, &query.DeleteMemberRequest{})
	require.Error(t, err)
	assert.EqualError(t, err, "orgID or userID is required")
}
