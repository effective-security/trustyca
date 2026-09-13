package model_test

import (
	"testing"
	"time"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/xdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_APIKey_Validate(t *testing.T) {
	t.Parallel()

	valid := func() *model.APIKey {
		return &model.APIKey{
			OrgID:  xdb.NewID(1),
			Label:  "ci",
			Key:    "sk_1_abc",
			Secret: "protected",
			Scopes: []string{"org:read"},
			Status: pb.ItemStatus_Active,
		}
	}
	require.NoError(t, valid().Validate())

	k := valid()
	k.OrgID = xdb.ID{}
	assert.EqualError(t, k.Validate(), "invalid org ID")
	k = valid()
	k.Label = ""
	assert.EqualError(t, k.Validate(), "invalid label length")
	k = valid()
	k.Status = pb.ItemStatus_Unknown
	assert.EqualError(t, k.Validate(), "invalid key status")
	k = valid()
	k.Key = ""
	assert.EqualError(t, k.Validate(), "invalid key length")
	k = valid()
	k.Scopes = nil
	assert.EqualError(t, k.Validate(), "invalid scopes")
	k = valid()
	k.Scopes = []string{""}
	assert.EqualError(t, k.Validate(), "invalid scope length: ")
}

func Test_APIKey_Pb(t *testing.T) {
	t.Parallel()

	k := &model.APIKey{
		ID:        xdb.NewID(5),
		OrgID:     xdb.NewID(1),
		ProjectID: xdb.NewID(201),
		Label:     "ci",
		Key:       "sk_1_abc",
		Secret:    "protected",
		Scopes:    []string{"org:read", "certs:issue"},
		Status:    pb.ItemStatus_Active,
		ExpiresAt: xdb.Time(time.Now().Add(-time.Hour)),
		UsedCount: 3,
	}
	pk := k.Pb()
	assert.Equal(t, "5", pk.ID)
	assert.Equal(t, "1", pk.OrgID)
	assert.Equal(t, "201", pk.ProjectID)
	assert.Equal(t, []string{"org:read", "certs:issue"}, pk.Scopes)
	assert.Empty(t, pk.Secret, "the secret is never returned by Pb")
	assert.EqualValues(t, 3, pk.UsedCount)
	assert.True(t, k.IsExpired(time.Now()))
	k.ExpiresAt = xdb.Time{}
	assert.False(t, k.IsExpired(time.Now()), "no expiry never expires")

	res := (&model.APIKeyResult{Rows: model.APIKeySlice{k}, HasNextPage: true, NextOffset: 10}).Pb()
	require.Len(t, res.APIKeys, 1)
	require.NotNil(t, res.NextPage)
	assert.EqualValues(t, 10, res.NextPage.Offset)
}
