package pgsql_test

import (
	"testing"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Org(t *testing.T) {
	userID := provider.NextID()
	login := &model.Login{
		ID:         userID,
		ExternalID: userID.String(),
		Name:       "Test User",
		Email:      userID.String() + "@example.com",
		Provider:   pb.IDP_Github,
	}
	login, user, err := provider.LoginUser(ctx, login)
	require.NoError(t, err)
	defer func() {
		_, err := provider.DeleteUserByEmail(ctx, login.Email)
		assert.NoError(t, err)
	}()

	org := &model.Org{
		Name: "Test Org",
	}
	org, err = provider.RegisterOrg(ctx, org, user.ID.UInt64())
	require.NoError(t, err)
	defer func() {
		_, err := provider.DeleteOrg(ctx, org.ID.UInt64())
		assert.NoError(t, err)
	}()
	assert.Equal(t, pb.ItemStatus_Active, org.Status)

	org2, err := provider.GetOrg(ctx, org.ID.UInt64())
	require.NoError(t, err)
	assert.Equal(t, org, org2)

	org2, err = provider.FindOrg(ctx, org.Alias)
	require.NoError(t, err)
	assert.Equal(t, org, org2)

	orgs, err := provider.ListOrgs(ctx, &query.ListOrgsRequest{})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(orgs.Rows), 1)

	memberships, err := provider.ListMemberships(ctx, &query.ListMembershipsRequest{OrgID: org.ID.UInt64()})
	require.NoError(t, err)
	require.Equal(t, 1, len(memberships))
	assert.Equal(t, org.ID.UInt64(), memberships[0].OrgID.UInt64())
	assert.Equal(t, user.ID.UInt64(), memberships[0].UserID.UInt64())
	assert.Equal(t, pb.Role_Owner, memberships[0].Role)

	userOrgs, err := provider.GetUserOrgs(ctx, user.ID.UInt64())
	require.NoError(t, err)
	require.Len(t, userOrgs, 1)
	assert.Equal(t, org.ID.UInt64(), userOrgs[0].ID.UInt64())

	updated, err := provider.UpdateOrg(ctx, &query.UpdateOrgRequest{ID: org.ID.UInt64(), Name: "new name", Description: "new description"})
	require.NoError(t, err)
	assert.Equal(t, "new name", updated.Name)
	assert.Equal(t, "new description", string(updated.Description))
	assert.Equal(t, org.Alias, updated.Alias)

	updated, err = provider.UpdateOrg(ctx, &query.UpdateOrgRequest{ID: org.ID.UInt64(), Status: pb.ItemStatus_Inactive})
	require.NoError(t, err)
	assert.Equal(t, pb.ItemStatus_Inactive, updated.Status)
}

func Test_Org_NotFound(t *testing.T) {
	_, err := provider.GetOrg(ctx, 123)
	assert.EqualError(t, err, "record not found: org: 123")

	_, err = provider.FindOrg(ctx, "cp_does-not-exist")
	assert.EqualError(t, err, "record not found: org: cp_does-not-exist")
}

func Test_UpdateOrg(t *testing.T) {
	userID := provider.NextID()
	login := &model.Login{
		ID:         userID,
		ExternalID: userID.String(),
		Name:       "Test Update Org User",
		Email:      userID.String() + "@example.com",
		Provider:   pb.IDP_Github,
	}
	_, user, err := provider.LoginUser(ctx, login)
	require.NoError(t, err)
	defer func() {
		_, err := provider.DeleteUserByEmail(ctx, login.Email)
		assert.NoError(t, err)
	}()

	org, err := provider.RegisterOrg(ctx, &model.Org{Name: "Original Name"}, user.ID.UInt64())
	require.NoError(t, err)
	defer func() {
		_, err := provider.DeleteOrg(ctx, org.ID.UInt64())
		assert.NoError(t, err)
	}()

	updated, err := provider.UpdateOrg(ctx, &query.UpdateOrgRequest{ID: org.ID.UInt64(), Name: "Updated Name", Description: "Updated description"})
	require.NoError(t, err)
	assert.Equal(t, "Updated Name", updated.Name)
	assert.Equal(t, "Updated description", string(updated.Description))
	assert.Equal(t, org.Alias, updated.Alias)

	_, err = provider.UpdateOrg(ctx, &query.UpdateOrgRequest{ID: org.ID.UInt64(), Name: "", Description: ""})
	assert.EqualError(t, err, "no changes to update")

	_, err = provider.UpdateOrg(ctx, &query.UpdateOrgRequest{ID: 123, Name: "Some Name", Description: ""})
	assert.EqualError(t, err, "record not found: org: 123")
}
