package orgs

import (
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/mocks/mocktrustycadb"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xpki/dataprotection"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestService_APIKeys(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	dp, err := dataprotection.NewSymmetric([]byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, err)

	db := mocktrustycadb.NewMockOrgsDb(ctrl)
	db.EXPECT().TryCreateEvent(gomock.Any()).AnyTimes()
	db.EXPECT().NextID().Return(xdb.NewID(555)).AnyTimes()
	svc := Service{db: db, authorizer: newFakeAuthorizer(orgGrant(42, pb.Role_Admin)), dataprotection: dp}
	ctx := testCtx("42", "1")

	// validation
	_, err = svc.CreateAPIKey(testCtx("42", ""), &pb.CreateAPIKeyRequest{Label: "k"})
	assert.EqualError(t, err, "unauthorized: org not selected")
	_, err = svc.CreateAPIKey(ctx, &pb.CreateAPIKeyRequest{})
	assert.EqualError(t, err, "bad_request: label is required")
	_, err = svc.CreateAPIKey(ctx, &pb.CreateAPIKeyRequest{Label: "k", Scopes: []string{"billing:write"}})
	assert.EqualError(t, err, "bad_request: unknown scope: billing:write")
	_, err = svc.CreateAPIKey(ctx, &pb.CreateAPIKeyRequest{Label: "k", ProjectID: "bad"})
	assert.EqualError(t, err, "bad_request: invalid project ID")
	_, err = svc.CreateAPIKey(ctx, &pb.CreateAPIKeyRequest{Label: "k", ProjectID: "301"})
	assert.EqualError(t, err, "not_found: project not found", "project of another org")
	_, err = svc.CreateAPIKey(ctx, &pb.CreateAPIKeyRequest{Label: "k", ExpiresAt: "2001-01-01T00:00:00Z"})
	assert.EqualError(t, err, "bad_request: invalid expiration time")

	// create: default scopes, the key carries the org and the protected ID,
	// the secret is stored protected and returned once
	db.EXPECT().RegisterAPIKey(gomock.Any(), gomock.Any()).DoAndReturn(func(_ any, m *model.APIKey) (*model.APIKey, error) {
		assert.Equal(t, uint64(555), m.ID.UInt64())
		assert.Equal(t, uint64(1), m.OrgID.UInt64())
		assert.Equal(t, uint64(201), m.ProjectID.UInt64())
		assert.Equal(t, []string{"org:read", "project:read", "ca:read"}, []string(m.Scopes))
		assert.Equal(t, pb.ItemStatus_Active, m.Status)
		assert.True(t, len(m.Key) > len("sk_1_"))
		assert.Contains(t, m.Key, "sk_1_")
		assert.False(t, m.ExpiresAt.IsZero())
		var secret string
		require.NoError(t, dataprotection.UnprotectObject(t.Context(), dp, m.Secret, &secret))
		assert.Len(t, secret, 32)
		res := *m
		return &res, nil
	})
	key, err := svc.CreateAPIKey(ctx, &pb.CreateAPIKeyRequest{Label: "ci", ProjectID: "201"})
	require.NoError(t, err)
	assert.Equal(t, "555", key.ID)
	assert.Equal(t, "201", key.ProjectID)
	assert.Len(t, key.Secret, 32, "the clear secret is returned once")
	assert.Equal(t, []string{"org:read", "project:read", "ca:read"}, key.Scopes)

	db.EXPECT().RegisterAPIKey(gomock.Any(), gomock.Any()).Return(nil, errors.New("db failed"))
	_, err = svc.CreateAPIKey(ctx, &pb.CreateAPIKeyRequest{Label: "ci", Scopes: []string{"certs:*"}, ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)})
	assert.EqualError(t, err, "unexpected: failed to register API key")

	// list
	stored := &model.APIKey{ID: xdb.NewID(555), OrgID: xdb.NewID(1), ProjectID: xdb.NewID(201), Label: "ci", Key: "sk_1_x", Secret: "protected", Scopes: []string{"org:read"}, Status: pb.ItemStatus_Active}
	db.EXPECT().ListAPIKeys(gomock.Any(), &query.ListAPIKeysRequest{OrgID: 1, ProjectID: 201, Limit: 100}).Return(&model.APIKeyResult{Rows: model.APIKeySlice{stored}}, nil)
	list, err := svc.ListAPIKeys(ctx, &pb.ListAPIKeysRequest{ProjectID: "201"})
	require.NoError(t, err)
	require.Len(t, list.APIKeys, 1)
	assert.Empty(t, list.APIKeys[0].Secret, "secrets are never listed")
	assert.Equal(t, "sk_1_x", list.APIKeys[0].Key)

	_, err = svc.ListAPIKeys(testCtx("42", ""), &pb.ListAPIKeysRequest{})
	assert.EqualError(t, err, "unauthorized: org not selected")
	db.EXPECT().ListAPIKeys(gomock.Any(), gomock.Any()).Return(nil, errors.New("db failed"))
	_, err = svc.ListAPIKeys(ctx, &pb.ListAPIKeysRequest{})
	assert.EqualError(t, err, "unexpected: failed to list API keys")

	// delete
	_, err = svc.DeleteAPIKey(ctx, &pb.APIKeyRequest{ID: "bad"})
	assert.EqualError(t, err, "bad_request: invalid ID")
	db.EXPECT().GetAPIKey(gomock.Any(), uint64(1), uint64(555)).Return(nil, errors.New("record not found"))
	_, err = svc.DeleteAPIKey(ctx, &pb.APIKeyRequest{ID: "555"})
	assert.EqualError(t, err, "not_found: unable to get API key")

	db.EXPECT().GetAPIKey(gomock.Any(), uint64(1), uint64(555)).Return(stored, nil)
	_, err = svc.DeleteAPIKey(ctx, &pb.APIKeyRequest{ID: "555", ProjectID: "202"})
	assert.EqualError(t, err, "not_found: API key not found in the project")

	db.EXPECT().GetAPIKey(gomock.Any(), uint64(1), uint64(555)).Return(stored, nil)
	db.EXPECT().DeleteAPIKey(gomock.Any(), uint64(1), uint64(555)).Return(int64(1), nil)
	res, err := svc.DeleteAPIKey(ctx, &pb.APIKeyRequest{ID: "555", ProjectID: "201"})
	require.NoError(t, err)
	assert.EqualValues(t, 1, res.Deleted)
}
