package pgsql_test

import (
	"testing"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
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

	updated, err := provider.UpdateMemberRole(ctx, org.ID.UInt64(), user.ID.UInt64(), pb.Role_Admin)
	require.NoError(t, err)
	assert.Equal(t, pb.Role_Admin, updated.Role)

	count, err := provider.DeleteMember(ctx, &query.DeleteMemberRequest{
		OrgID:  org.ID.UInt64(),
		UserID: user.ID.UInt64(),
	})
	require.NoError(t, err)
	assert.EqualValues(t, 1, count)

	memberships, err = provider.ListMemberships(ctx, &query.ListMembershipsRequest{OrgID: org.ID.UInt64()})
	require.NoError(t, err)
	assert.Empty(t, memberships)
}

func Test_UpdateMemberRole_NotFound(t *testing.T) {
	_, err := provider.UpdateMemberRole(ctx, 123, 456, pb.Role_Admin)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "record not found")
}

func Test_DeleteMember_InvalidRequest(t *testing.T) {
	_, err := provider.DeleteMember(ctx, &query.DeleteMemberRequest{})
	require.Error(t, err)
	assert.EqualError(t, err, "orgID or userID is required")
}
