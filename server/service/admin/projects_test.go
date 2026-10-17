package admin

import (
	"context"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/mocks/mocktrustycadb"
	"github.com/effective-security/trustyca/privpb"
	"github.com/effective-security/xdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestService_ListProjects(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := mocktrustycadb.NewMockOrgsDb(ctrl)
	svc := Service{
		db: db,
	}

	db.EXPECT().ListProjects(ctx, gomock.Any()).Return(&model.ProjectResult{
		Rows: []*model.Project{
			{
				ID:          xdb.NewID(1),
				Name:        "Project 1",
				Description: "Project 1 Description",
			},
			{
				ID:          xdb.NewID(2),
				Name:        "Project 2",
				Description: "Project 2 Description",
			},
		},
		HasNextPage: true,
		NextOffset:  1,
	}, nil)

	res, err := svc.ListProjects(ctx, &privpb.ListProjectsRequest{})
	assert.NoError(t, err)
	assert.Equal(t, len(res.Projects), 2)
	require.NotNil(t, res.NextPage)
	assert.Equal(t, 1, int(res.NextPage.Offset))

	db.EXPECT().ListProjects(ctx, gomock.Any()).Return(nil, errors.New("something happened"))
	_, err = svc.ListProjects(ctx, &privpb.ListProjectsRequest{})
	assert.EqualError(t, err, "unexpected: failed to list projects")
}
