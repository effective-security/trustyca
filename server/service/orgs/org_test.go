package orgs

import (
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/mocks/mocktrustycadb"
	"github.com/effective-security/xdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestService_Org(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := mocktrustycadb.NewMockOrgsDb(ctrl)
	db.EXPECT().TryCreateEvent(gomock.Any()).AnyTimes()
	az := newFakeAuthorizer(orgGrant(42, pb.Role_Owner))
	svc := Service{db: db, authorizer: az}

	morg := &model.Org{
		ID:          xdb.NewID(1),
		Name:        "Test Org",
		Description: "Test Description",
		Status:      pb.ItemStatus_Active,
	}

	ctx := testCtx("42", "1")
	noOrg := testCtx("42", "")

	// register: the caller becomes Owner and the cache is invalidated
	db.EXPECT().RegisterOrg(gomock.Any(), gomock.Any(), uint64(42)).Return(morg, nil)
	org, err := svc.RegisterOrg(noOrg, &pb.RegisterOrgRequest{Name: "Test Org", Description: "Test Description"})
	require.NoError(t, err)
	assert.Equal(t, "1", org.ID)
	assert.Equal(t, "Test Org", org.Name)
	assert.Equal(t, pb.ItemStatus_Active, org.Status)
	assert.Contains(t, az.invalidated, "user:42")

	db.EXPECT().RegisterOrg(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, errors.New("name is required"))
	_, err = svc.RegisterOrg(ctx, &pb.RegisterOrgRequest{Name: "Test Org"})
	assert.EqualError(t, err, "unexpected: failed to register org")

	// get: org from the token
	db.EXPECT().GetOrg(gomock.Any(), uint64(1)).Return(morg, nil)
	org, err = svc.GetOrg(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	assert.Equal(t, "1", org.ID)

	_, err = svc.GetOrg(noOrg, &emptypb.Empty{})
	assert.EqualError(t, err, "unauthorized: org not selected")

	db.EXPECT().GetOrg(gomock.Any(), uint64(1)).Return(nil, errors.New("not found"))
	_, err = svc.GetOrg(ctx, &emptypb.Empty{})
	assert.EqualError(t, err, "not_found: failed to get org")

	// update
	db.EXPECT().UpdateOrg(gomock.Any(), &query.UpdateOrgRequest{ID: 1, Name: "Updated Org", Description: "Updated Description"}).Return(&model.Org{
		ID:          xdb.NewID(1),
		Name:        "Updated Org",
		Description: "Updated Description",
		Status:      pb.ItemStatus_Active,
	}, nil)
	org, err = svc.UpdateOrg(ctx, &pb.UpdateOrgRequest{Name: "Updated Org", Description: "Updated Description"})
	require.NoError(t, err)
	assert.Equal(t, "Updated Org", org.Name)

	_, err = svc.UpdateOrg(noOrg, &pb.UpdateOrgRequest{Name: "x"})
	assert.EqualError(t, err, "unauthorized: org not selected")

	db.EXPECT().UpdateOrg(gomock.Any(), gomock.Any()).Return(nil, errors.New("not found"))
	_, err = svc.UpdateOrg(ctx, &pb.UpdateOrgRequest{Name: "x"})
	assert.EqualError(t, err, "not_found: failed to update org")

	// delete deactivates the org from the token
	db.EXPECT().UpdateOrg(gomock.Any(), &query.UpdateOrgRequest{ID: 1, Status: pb.ItemStatus_Inactive}).Return(morg, nil)
	org, err = svc.DeleteOrg(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	assert.Equal(t, "1", org.ID)

	_, err = svc.DeleteOrg(noOrg, &emptypb.Empty{})
	assert.EqualError(t, err, "unauthorized: org not selected")

	db.EXPECT().UpdateOrg(gomock.Any(), gomock.Any()).Return(nil, errors.New("not found"))
	_, err = svc.DeleteOrg(ctx, &emptypb.Empty{})
	assert.EqualError(t, err, "not_found: failed to update org status")
}
