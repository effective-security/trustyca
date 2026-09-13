package pgsql_test

import (
	"testing"
	"time"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xpki/certutil"
	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_APIKey(t *testing.T) {
	_, org := setupOwnerAndOrg(t, "Test_APIKey")

	_, err := provider.RegisterAPIKey(ctx, &model.APIKey{
		OrgID:  org.ID,
		Key:    "test-key",
		Secret: "test-secret",
	})
	assert.EqualError(t, err, "invalid label length")

	project, err := provider.RegisterProject(ctx, &model.Project{OrgID: org.ID, Name: "Keys"})
	require.NoError(t, err)

	km := &model.APIKey{
		OrgID:  org.ID,
		Label:  "org key",
		Key:    certutil.RandomString(32),
		Secret: certutil.RandomString(32),
		Scopes: []string{"org:read", "certs:read"},
	}
	orgKey, err := provider.RegisterAPIKey(ctx, km)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = provider.DeleteAPIKey(ctx, org.ID.UInt64(), orgKey.ID.UInt64())
	})
	assert.Equal(t, org.ID.UInt64(), orgKey.OrgID.UInt64())
	assert.Equal(t, km.Label, orgKey.Label)
	assert.Equal(t, km.Key, orgKey.Key)
	assert.Equal(t, km.Secret, orgKey.Secret)
	assert.Equal(t, pq.StringArray{"org:read", "certs:read"}, orgKey.Scopes)
	assert.Equal(t, pb.ItemStatus_Active, orgKey.Status, "status defaults to Active")
	assert.EqualValues(t, 0, orgKey.UsedCount)

	// the key is unique
	_, err = provider.RegisterAPIKey(ctx, &model.APIKey{
		OrgID: org.ID, Label: "dup", Key: km.Key, Secret: "s", Scopes: []string{"org:read"},
	})
	require.Error(t, err)

	projectKey, err := provider.RegisterAPIKey(ctx, &model.APIKey{
		OrgID:     org.ID,
		ProjectID: project.ID,
		Label:     "project key",
		Key:       certutil.RandomString(32),
		Secret:    certutil.RandomString(32),
		Scopes:    []string{"certs:issue"},
		ExpiresAt: xdb.Time(time.Now().Add(-time.Hour)),
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = provider.DeleteAPIKey(ctx, org.ID.UInt64(), projectKey.ID.UInt64())
	})
	assert.True(t, projectKey.IsExpired(time.Now()))

	// get is org scoped
	got, err := provider.GetAPIKey(ctx, org.ID.UInt64(), orgKey.ID.UInt64())
	require.NoError(t, err)
	assert.Equal(t, orgKey.Key, got.Key)
	_, err = provider.GetAPIKey(ctx, org.ID.UInt64()+1, orgKey.ID.UInt64())
	assert.ErrorContains(t, err, "record not found")

	// list: all, by project, by scopes held
	list, err := provider.ListAPIKeys(ctx, &query.ListAPIKeysRequest{OrgID: org.ID.UInt64(), Limit: 10})
	require.NoError(t, err)
	require.Len(t, list.Rows, 2)
	assert.False(t, list.HasNextPage)

	list, err = provider.ListAPIKeys(ctx, &query.ListAPIKeysRequest{OrgID: org.ID.UInt64(), ProjectID: project.ID.UInt64(), Limit: 10})
	require.NoError(t, err)
	require.Len(t, list.Rows, 1)
	assert.Equal(t, projectKey.ID.UInt64(), list.Rows[0].ID.UInt64())

	list, err = provider.ListAPIKeys(ctx, &query.ListAPIKeysRequest{OrgID: org.ID.UInt64(), Scopes: []string{"certs:read", "org:read"}, Limit: 10})
	require.NoError(t, err)
	require.Len(t, list.Rows, 1)
	assert.Equal(t, orgKey.ID.UInt64(), list.Rows[0].ID.UInt64())

	list, err = provider.ListAPIKeys(ctx, &query.ListAPIKeysRequest{OrgID: org.ID.UInt64(), Key: orgKey.Key, Status: pb.ItemStatus_Active, Limit: 10})
	require.NoError(t, err)
	require.Len(t, list.Rows, 1)

	// use increments the counter
	used, err := provider.UseAPIKey(ctx, org.ID.UInt64(), orgKey.ID.UInt64())
	require.NoError(t, err)
	assert.EqualValues(t, 1, used.UsedCount)
	assert.False(t, used.UsedAt.IsZero())
	_, err = provider.UseAPIKey(ctx, org.ID.UInt64(), 12345)
	assert.ErrorContains(t, err, "record not found")

	// delete is org scoped
	n, err := provider.DeleteAPIKey(ctx, org.ID.UInt64()+1, orgKey.ID.UInt64())
	require.NoError(t, err)
	assert.EqualValues(t, 0, n)
	n, err = provider.DeleteAPIKey(ctx, org.ID.UInt64(), orgKey.ID.UInt64())
	require.NoError(t, err)
	assert.EqualValues(t, 1, n)
	_, err = provider.GetAPIKey(ctx, org.ID.UInt64(), orgKey.ID.UInt64())
	assert.ErrorContains(t, err, "record not found")
}
