package pgsql_test

import (
	"fmt"
	"testing"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/xdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoginUser(t *testing.T) {
	id := provider.NextID()
	name := fmt.Sprintf("user-%d", id.UInt64())
	email := name + "@trustyca.com"

	u1 := &model.Login{
		Provider:     pb.IDP_Google,
		Name:         name,
		Email:        email,
		AccessToken:  "12334",
		RefreshToken: "rt1",
		ExternalID:   fmt.Sprintf("%d", id.UInt64()+13),
	}
	u2 := &model.Login{
		Provider:     pb.IDP_Github,
		Name:         name,
		Email:        email,
		AccessToken:  "12335",
		RefreshToken: "rt2",
		ExternalID:   fmt.Sprintf("%d", id.UInt64()+17),
	}

	login1, user, err := provider.LoginUser(ctx, u1)
	require.NoError(t, err)
	defer func() {
		_, err := provider.DeleteUserByEmail(ctx, u1.Email)
		assert.NoError(t, err)
	}()

	assert.NotNil(t, user)
	assert.Equal(t, name, user.Name)
	assert.Equal(t, email, user.Email)
	// the first login should create a new user with the same ID
	assert.Equal(t, login1.ID.UInt64(), user.ID.UInt64())
	assert.Equal(t, uint32(1), login1.Count)

	login2, guser, err := provider.LoginUser(ctx, u2)
	require.NoError(t, err)
	defer func() {
		_, err := provider.DeleteUserByEmail(ctx, u2.Email)
		assert.NoError(t, err)
	}()

	assert.NotNil(t, guser)
	assert.Equal(t, name, guser.Name)
	assert.Equal(t, email, guser.Email)
	require.Equal(t, user.ID, guser.ID)
	assert.NotEqual(t, login2.ID.UInt64(), guser.ID.UInt64())
	assert.Equal(t, user.ID.UInt64(), guser.ID.UInt64())
	assert.Equal(t, uint32(1), login2.Count)

	login1x, user2, err := provider.LoginUser(ctx, u1)
	require.NoError(t, err)
	assert.NotNil(t, user2)
	assert.Equal(t, name, user2.Name)
	assert.Equal(t, user.ID, user2.ID)
	assert.Equal(t, uint32(2), login1x.Count)

	user3, err := provider.GetUser(ctx, user2.ID.UInt64())
	require.NoError(t, err)
	require.NotNil(t, user3)
	assert.Equal(t, name, user3.Name)

	user4, err := provider.GetUserByEmail(ctx, email)
	require.NoError(t, err)
	require.NotNil(t, user4)
	assert.Equal(t, user3, user3)

	list, err := provider.GetLoginsByEmail(ctx, user2.Email)
	require.NoError(t, err)
	assert.Len(t, list, 2)

	// TODO: this test fails as soon as there are more than 500 users
	// The users/logins are not cleaned up after some tests properly.
	// make drop-sql start-sql
	list2, next, err := provider.ListLogins(ctx, xdb.DefaultPageSize, 0)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(list2), len(list))
	assert.Equal(t, uint32(0), next)
}

func TestGetUsersByEmail(t *testing.T) {
	list, err := provider.GetLoginsByEmail(ctx, "denis@trustyca.com")
	require.NoError(t, err)
	assert.Empty(t, list)

	_, err = provider.GetUser(ctx, 123)
	assert.EqualError(t, err, "record not found: user: 123")

	_, err = provider.GetUserByEmail(ctx, "123")
	assert.EqualError(t, err, "record not found: user: 123")
}

func TestUpdateUser(t *testing.T) {
	id := provider.NextID()
	email := id.String() + "@trustyca.com"
	login := &model.Login{
		ID:         id,
		ExternalID: id.String(),
		Name:       "Original Name",
		Email:      email,
		Provider:   pb.IDP_Google,
	}
	_, user, err := provider.LoginUser(ctx, login)
	require.NoError(t, err)
	defer func() {
		_, err := provider.DeleteUserByEmail(ctx, email)
		assert.NoError(t, err)
	}()

	updated, err := provider.UpdateUser(ctx, user.ID.UInt64(), "Updated Name", true)
	require.NoError(t, err)
	assert.Equal(t, "Updated Name", updated.Name)
	assert.True(t, updated.EmailVerified)

	_, err = provider.UpdateUser(ctx, user.ID.UInt64(), "", false)
	assert.EqualError(t, err, `invalid name: ""`)

	_, err = provider.UpdateUser(ctx, 123, "Some Name", false)
	assert.EqualError(t, err, "record not found: user: 123")
}

func TestDeleteUser(t *testing.T) {
	id := provider.NextID()
	email := id.String() + "@trustyca.com"
	login := &model.Login{
		ID:         id,
		ExternalID: id.String(),
		Name:       "Delete Me",
		Email:      email,
		Provider:   pb.IDP_Google,
	}
	_, user, err := provider.LoginUser(ctx, login)
	require.NoError(t, err)

	counts, err := provider.DeleteUser(ctx, user.ID.UInt64())
	require.NoError(t, err)
	assert.EqualValues(t, 1, counts["trustyca.login"])
	assert.EqualValues(t, 1, counts["trustyca.user"])

	_, err = provider.GetUser(ctx, user.ID.UInt64())
	assert.ErrorContains(t, err, "record not found")

	_, err = provider.DeleteUser(ctx, 123)
	assert.EqualError(t, err, "record not found: user: 123")
}

func TestGetAndDeleteLogin(t *testing.T) {
	id := provider.NextID()
	email := id.String() + "@trustyca.com"
	login := &model.Login{
		ID:         id,
		ExternalID: id.String(),
		Name:       "Login User",
		Email:      email,
		Provider:   pb.IDP_Google,
	}
	loggedIn, _, err := provider.LoginUser(ctx, login)
	require.NoError(t, err)
	defer func() {
		_, err := provider.DeleteUserByEmail(ctx, email)
		assert.NoError(t, err)
	}()

	got, err := provider.GetLogin(ctx, loggedIn.ID.UInt64())
	require.NoError(t, err)
	assert.Equal(t, loggedIn.Email, got.Email)

	count, err := provider.DeleteLogin(ctx, loggedIn.ID.UInt64())
	require.NoError(t, err)
	assert.EqualValues(t, 1, count)

	_, err = provider.GetLogin(ctx, loggedIn.ID.UInt64())
	assert.ErrorContains(t, err, "record not found")
}
