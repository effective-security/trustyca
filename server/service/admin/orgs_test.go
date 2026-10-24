package admin

import (
	"context"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/mocks/mocktrustycadb"
	"github.com/effective-security/trustyca/privpb"
	"github.com/effective-security/xdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestService_ListOrgs(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := mocktrustycadb.NewMockOrgsDb(ctrl)
	svc := Service{
		db: db,
	}

	db.EXPECT().ListOrgs(ctx, gomock.Any()).Return(&model.OrgResult{
		Rows: []*model.Org{
			{
				ID:          xdb.NewID(1),
				Name:        "Org 1",
				Description: "Org 1 Description",
			},
			{
				ID:          xdb.NewID(2),
				Name:        "Org 2",
				Description: "Org 2 Description",
			},
		},
		HasNextPage: true,
		NextOffset:  1,
	}, nil)

	res, err := svc.ListOrgs(ctx, &privpb.ListOrgsRequest{})
	assert.NoError(t, err)
	assert.Equal(t, len(res.Orgs), 2)
	require.NotNil(t, res.NextPage)
	assert.Equal(t, 1, int(res.NextPage.Offset))

	// the cursor of the previous page continues the listing by name
	next := query.EncodeNameCursor("Org 2", xdb.NewID(2))
	cursor, err := query.ParseNameCursor(next)
	require.NoError(t, err)
	db.EXPECT().ListOrgs(ctx, &query.ListOrgsRequest{Limit: 10, Cursor: cursor}).Return(&model.OrgResult{
		HasNextPage: true,
		Cursor:      next,
	}, nil)
	res, err = svc.ListOrgs(ctx, &privpb.ListOrgsRequest{Limit: 10, Cursor: next})
	require.NoError(t, err)
	require.NotNil(t, res.NextPage)
	assert.Equal(t, next, res.NextPage.Cursor)
	assert.Zero(t, res.NextPage.Offset)

	_, err = svc.ListOrgs(ctx, &privpb.ListOrgsRequest{Cursor: "not a cursor"})
	assert.EqualError(t, err, "bad_request: invalid cursor")

	db.EXPECT().ListOrgs(ctx, gomock.Any()).Return(nil, errors.New("something happened"))
	_, err = svc.ListOrgs(ctx, &privpb.ListOrgsRequest{})
	assert.EqualError(t, err, "unexpected: failed to list orgs")
}
