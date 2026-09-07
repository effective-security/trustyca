package pgsql_test

import (
	"testing"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Invite(t *testing.T) {
	owner, org := setupOwnerAndOrg(t, "Test_Invite")

	inviteeEmail := provider.NextID().String() + "@example.com"
	inviteeEmail2 := provider.NextID().String() + "@example.com"
	invite, err := provider.CreateInvite(ctx, &model.Invite{
		OrgID:     org.ID,
		InviterID: owner.ID,
		Email:     inviteeEmail,
		Role:      pb.Role_User,
	})
	require.NoError(t, err)
	assert.Equal(t, inviteeEmail, invite.Email)
	assert.Equal(t, pb.Role_User, invite.Role)

	got, err := provider.GetInvite(ctx, invite.ID.UInt64())
	require.NoError(t, err)
	assert.Equal(t, invite.ID, got.ID)

	got2, err := provider.GetInviteByOrgAndEmail(ctx, org.ID.UInt64(), inviteeEmail)
	require.NoError(t, err)
	assert.Equal(t, invite.ID, got2.ID)

	list, err := provider.GetOrgInvites(ctx, org.ID.UInt64())
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, invite.ID, list[0].ID)

	list, err = provider.GetUserInvites(ctx, inviteeEmail)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, invite.ID, list[0].ID)

	// re-inviting with a different role updates the existing invite
	invite2, err := provider.CreateInvite(ctx, &model.Invite{
		OrgID:     org.ID,
		InviterID: owner.ID,
		Email:     inviteeEmail,
		Role:      pb.Role_Admin,
	})
	require.NoError(t, err)
	assert.Equal(t, pb.Role_Admin, invite2.Role)

	count, err := provider.DeleteInvite(ctx, &query.DeleteInviteRequest{
		OrgID: org.ID.UInt64(),
		Email: inviteeEmail,
	})
	require.NoError(t, err)
	assert.EqualValues(t, 1, count)

	_, err = provider.GetInvite(ctx, invite.ID.UInt64())
	assert.ErrorContains(t, err, "record not found")

	invite3, err := provider.CreateInvite(ctx, &model.Invite{
		OrgID:     org.ID,
		InviterID: owner.ID,
		Email:     inviteeEmail2,
		Role:      pb.Role_User,
	})
	require.NoError(t, err)
	assert.Equal(t, pb.Role_User, invite3.Role)

	count, err = provider.DeleteInviteByID(ctx, invite3.ID.UInt64())
	require.NoError(t, err)
	assert.EqualValues(t, 1, count)

	_, err = provider.GetInvite(ctx, invite3.ID.UInt64())
	assert.ErrorContains(t, err, "record not found")
}

func Test_Invite_InvalidRequests(t *testing.T) {
	owner, org := setupOwnerAndOrg(t, "Test_Invite_Invalid")

	_, err := provider.CreateInvite(ctx, &model.Invite{
		InviterID: owner.ID,
		Email:     "someone@example.com",
		Role:      pb.Role_User,
	})
	assert.EqualError(t, err, "invalid org_id")

	_, err = provider.DeleteInvite(ctx, &query.DeleteInviteRequest{})
	assert.EqualError(t, err, "orgID or email is required")

	_, err = provider.GetInvite(ctx, 123)
	assert.ErrorContains(t, err, "record not found")

	_ = org
}

func Test_AcceptInvite(t *testing.T) {
	owner, org := setupOwnerAndOrg(t, "Test_AcceptInvite")

	inviteeID := provider.NextID()
	inviteeLogin := &model.Login{
		ID:         inviteeID,
		ExternalID: inviteeID.String(),
		Name:       "Invitee",
		Email:      inviteeID.String() + "@example.com",
		Provider:   pb.IDP_Google,
	}
	_, invitee, err := provider.LoginUser(ctx, inviteeLogin)
	require.NoError(t, err)
	defer func() {
		_, err := provider.DeleteUserByEmail(ctx, inviteeLogin.Email)
		assert.NoError(t, err)
	}()

	invite, err := provider.CreateInvite(ctx, &model.Invite{
		OrgID:     org.ID,
		InviterID: owner.ID,
		Email:     invitee.Email,
		Role:      pb.Role_Admin,
	})
	require.NoError(t, err)

	membership, err := provider.AcceptInvite(ctx, invite.ID.UInt64(), invitee.ID.UInt64())
	require.NoError(t, err)
	assert.Equal(t, org.ID.UInt64(), membership.OrgID.UInt64())
	assert.Equal(t, invitee.ID.UInt64(), membership.UserID.UInt64())
	assert.Equal(t, pb.Role_Admin, membership.Role)

	// invite should be gone after acceptance
	_, err = provider.GetInvite(ctx, invite.ID.UInt64())
	assert.ErrorContains(t, err, "record not found")

	memberships, err := provider.ListMemberships(ctx, &query.ListMembershipsRequest{OrgID: org.ID.UInt64()})
	require.NoError(t, err)
	require.Len(t, memberships, 2) // owner + invitee
}

func Test_AcceptInvite_EmailMismatch(t *testing.T) {
	owner, org := setupOwnerAndOrg(t, "Test_AcceptInvite_Mismatch")

	otherID := provider.NextID()
	otherLogin := &model.Login{
		ID:         otherID,
		ExternalID: otherID.String(),
		Name:       "Other",
		Email:      otherID.String() + "@example.com",
		Provider:   pb.IDP_Google,
	}
	_, other, err := provider.LoginUser(ctx, otherLogin)
	require.NoError(t, err)
	defer func() {
		_, err := provider.DeleteUserByEmail(ctx, otherLogin.Email)
		assert.NoError(t, err)
	}()

	invite, err := provider.CreateInvite(ctx, &model.Invite{
		OrgID:     org.ID,
		InviterID: owner.ID,
		Email:     "someone-else@example.com",
		Role:      pb.Role_User,
	})
	require.NoError(t, err)
	defer func() {
		_, err := provider.DeleteInvite(ctx, &query.DeleteInviteRequest{OrgID: org.ID.UInt64(), Email: invite.Email})
		assert.NoError(t, err)
	}()

	_, err = provider.AcceptInvite(ctx, invite.ID.UInt64(), other.ID.UInt64())
	assert.EqualError(t, err, "invite email does not match user email")
}
