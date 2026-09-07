package orgs

import (
	"context"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/authctx"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/mocks/mocktrustycadb"
	"github.com/effective-security/xdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestService_RegisterOrg(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := mocktrustycadb.NewMockOrgsDb(ctrl)

	svc := Service{
		db:          db,
		roleChecker: authctx.NewRoleChecker(db),
	}

	morg := &model.Org{
		ID:          xdb.NewID(1),
		Name:        "Test Org",
		Description: "Test Description",
		Status:      pb.ItemStatus_Active,
	}

	db.EXPECT().RegisterOrg(gomock.Any(), gomock.Any(), gomock.Any()).Return(morg, nil)

	org, err := svc.RegisterOrg(ctx, &pb.RegisterOrgRequest{
		Name:        "Test Org",
		Description: "Test Description",
	})
	require.NoError(t, err)
	assert.Equal(t, "1", org.ID)
	assert.Equal(t, "Test Org", org.Name)
	assert.Equal(t, "Test Description", org.Description)
	assert.Equal(t, pb.ItemStatus_Active, org.Status)

	db.EXPECT().RegisterOrg(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, errors.New("name is required"))
	_, err = svc.RegisterOrg(ctx, &pb.RegisterOrgRequest{
		Name:        "Test Org",
		Description: "Test Description",
	})
	require.Error(t, err)
	assert.EqualError(t, err, "unexpected: failed to register org")

	db.EXPECT().GetOrg(gomock.Any(), gomock.Any()).Return(morg, nil)
	org, err = svc.GetOrg(ctx, &pb.GetOrgRequest{
		OrgID: "1",
	})
	require.NoError(t, err)
	assert.Equal(t, "1", org.ID)
	assert.Equal(t, "Test Org", org.Name)
	assert.Equal(t, "Test Description", org.Description)
	assert.Equal(t, pb.ItemStatus_Active, org.Status)

	_, err = svc.GetOrg(ctx, &pb.GetOrgRequest{})
	require.Error(t, err)
	assert.EqualError(t, err, "bad_request: invalid org ID")

	db.EXPECT().GetOrg(gomock.Any(), gomock.Any()).Return(nil, errors.New("not found"))
	_, err = svc.GetOrg(ctx, &pb.GetOrgRequest{OrgID: "1"})
	require.Error(t, err)
	assert.EqualError(t, err, "not_found: failed to get org")

	db.EXPECT().UpdateOrg(gomock.Any(), gomock.Any()).Return(&model.Org{
		ID:          xdb.NewID(1),
		Name:        "Updated Org",
		Description: "Updated Description",
		Alias:       "test-project",
		Status:      pb.ItemStatus_Active,
	}, nil)
	org, err = svc.UpdateOrg(ctx, &pb.UpdateOrgRequest{
		OrgID:       "1",
		Name:        "Updated Org",
		Description: "Updated Description",
	})
	require.NoError(t, err)
	assert.Equal(t, "1", org.ID)
	assert.Equal(t, "Updated Org", org.Name)
	assert.Equal(t, "Updated Description", org.Description)
	assert.Equal(t, pb.ItemStatus_Active, org.Status)

	_, err = svc.UpdateOrg(ctx, &pb.UpdateOrgRequest{})
	require.Error(t, err)
	assert.EqualError(t, err, "bad_request: invalid org ID")

	db.EXPECT().UpdateOrg(gomock.Any(), gomock.Any()).Return(nil, errors.New("not found"))
	_, err = svc.UpdateOrg(ctx, &pb.UpdateOrgRequest{OrgID: "1", Name: ""})
	require.Error(t, err)
	assert.EqualError(t, err, "not_found: failed to update org")

	db.EXPECT().UpdateOrg(gomock.Any(), gomock.Any()).Return(morg, nil)
	org, err = svc.DeleteOrg(ctx, &pb.DeleteOrgRequest{OrgID: "1"})
	require.NoError(t, err)
	assert.Equal(t, "1", org.ID)
	assert.Equal(t, "Test Org", org.Name)
	assert.Equal(t, "Test Description", org.Description)
	assert.Equal(t, pb.ItemStatus_Active, org.Status)

	_, err = svc.DeleteOrg(ctx, &pb.DeleteOrgRequest{})
	require.Error(t, err)
	assert.EqualError(t, err, "bad_request: invalid org ID")

	db.EXPECT().UpdateOrg(gomock.Any(), gomock.Any()).Return(nil, errors.New("not found"))
	_, err = svc.DeleteOrg(ctx, &pb.DeleteOrgRequest{OrgID: "1"})
	require.Error(t, err)
	assert.EqualError(t, err, "not_found: failed to update org status")
}
