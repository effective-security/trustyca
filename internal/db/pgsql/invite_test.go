package pgsql_test

import (
	"sync"
	"testing"
	"time"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/xdb"
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

	got2, err := provider.GetInviteByOrgAndEmail(ctx, org.ID.UInt64(), 0, inviteeEmail)
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
	// the refusal rolls back the delete: the invite stays pending
	_, err = provider.GetInvite(ctx, invite.ID.UInt64())
	assert.NoError(t, err)
}

// Test_AcceptInvite_Pending checks that an acceptance grants the invite as
// it is when it is deleted, and nothing for an invite that is gone or
// expired
func Test_AcceptInvite_Pending(t *testing.T) {
	owner, org := setupOwnerAndOrg(t, "Test_AcceptInvite_Pending")

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
	t.Cleanup(func() {
		_, err := provider.DeleteUserByEmail(ctx, inviteeLogin.Email)
		assert.NoError(t, err)
	})
	members := func() int {
		list, err := provider.ListMemberships(ctx, &query.ListMembershipsRequest{OrgID: org.ID.UInt64()})
		require.NoError(t, err)
		return len(list)
	}
	newInvite := func(expiresAt time.Time) *model.Invite {
		invite, err := provider.CreateInvite(ctx, &model.Invite{
			OrgID:     org.ID,
			InviterID: owner.ID,
			Email:     invitee.Email,
			Role:      pb.Role_Admin,
			ExpiresAt: xdb.Time(expiresAt),
		})
		require.NoError(t, err)
		t.Cleanup(func() {
			_, _ = provider.DeleteInviteByID(ctx, invite.ID.UInt64())
		})
		return invite
	}

	// a withdrawn invite grants nothing
	invite := newInvite(time.Now().Add(time.Hour))
	count, err := provider.DeleteInviteByID(ctx, invite.ID.UInt64())
	require.NoError(t, err)
	require.EqualValues(t, 1, count)
	_, err = provider.AcceptInvite(ctx, invite.ID.UInt64(), invitee.ID.UInt64())
	assert.ErrorContains(t, err, "record not found")
	assert.Equal(t, 1, members(), "the owner only")

	// an expired invite grants nothing and stays for the cleanup
	invite = newInvite(time.Now().Add(-time.Hour))
	_, err = provider.AcceptInvite(ctx, invite.ID.UInt64(), invitee.ID.UInt64())
	assert.EqualError(t, err, "invite expired")
	_, err = provider.GetInvite(ctx, invite.ID.UInt64())
	assert.NoError(t, err)
	assert.Equal(t, 1, members())

	// the invite is re-issued with another role and expiry: the row is
	// updated in place, and the grant has the role it has when it is taken
	invite = newInvite(time.Now().Add(time.Hour))
	_, err = provider.CreateInvite(ctx, &model.Invite{
		OrgID:     org.ID,
		InviterID: owner.ID,
		Email:     invitee.Email,
		Role:      pb.Role_Viewer,
	})
	require.NoError(t, err)

	// concurrent acceptances of one invite: the delete locks the row, so
	// only the first grants it and the others do not find it
	const callers = 4
	var (
		wg       sync.WaitGroup
		start    = make(chan struct{})
		granted  = make(chan *model.Membership, callers)
		notFound = make(chan error, callers)
	)
	for range callers {
		wg.Go(func() {
			<-start
			m, err := provider.AcceptInvite(ctx, invite.ID.UInt64(), invitee.ID.UInt64())
			if err != nil {
				notFound <- err
				return
			}
			granted <- m
		})
	}
	close(start)
	wg.Wait()
	close(granted)
	close(notFound)

	require.Len(t, granted, 1)
	m := <-granted
	assert.Equal(t, pb.Role_Viewer, m.Role, "the role of the re-issued invite")
	assert.Equal(t, invitee.ID.UInt64(), m.UserID.UInt64())
	assert.Len(t, notFound, callers-1)
	for err := range notFound {
		assert.ErrorContains(t, err, "record not found")
	}
	assert.Equal(t, 2, members())
	_, err = provider.GetInvite(ctx, invite.ID.UInt64())
	assert.ErrorContains(t, err, "record not found")
}

func Test_AcceptInvites_GrantFails(t *testing.T) {
	owner, org := setupOwnerAndOrg(t, "Test_AcceptInvites_GrantFails")

	inviteeID := provider.NextID()
	inviteeEmail := inviteeID.String() + "@example.com"
	invite, err := provider.CreateInvite(ctx, &model.Invite{
		OrgID:     org.ID,
		InviterID: owner.ID,
		Email:     inviteeEmail,
		Role:      pb.Role_User,
	})
	require.NoError(t, err)

	// the user is not registered: the grant violates its foreign key, and
	// the invite stays pending for a later login
	accepted, err := provider.AcceptInvites(ctx, &model.User{ID: inviteeID, Email: inviteeEmail})
	require.NoError(t, err)
	assert.Empty(t, accepted)

	pending, err := provider.GetUserInvites(ctx, inviteeEmail)
	require.NoError(t, err)
	require.Len(t, pending, 1)
	assert.Equal(t, invite.ID.UInt64(), pending[0].ID.UInt64())

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

	accepted, err = provider.AcceptInvites(ctx, invitee)
	require.NoError(t, err)
	require.Len(t, accepted, 1)
	assert.Equal(t, org.ID.UInt64(), accepted[0].OrgID.UInt64())
	assert.Equal(t, invitee.ID.UInt64(), accepted[0].UserID.UInt64())
	assert.Equal(t, pb.Role_User, accepted[0].Role)

	pending, err = provider.GetUserInvites(ctx, inviteeEmail)
	require.NoError(t, err)
	assert.Empty(t, pending)
}
