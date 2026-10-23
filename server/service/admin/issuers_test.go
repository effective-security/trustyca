package admin

import (
	"context"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/mocks/mocktrustycadb"
	"github.com/effective-security/trustyca/privpb"
	"github.com/effective-security/xdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestService_ListIssuers(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	caDb := mocktrustycadb.NewMockCaReadonlyDb(ctrl)
	svc := Service{
		ca: caDb,
	}
	rows := &model.IssuerResult{
		Rows: []*model.Issuer{
			{
				ID:     xdb.NewID(2),
				OrgID:  xdb.NewID(100),
				Label:  "issuing",
				Type:   pb.AuthorityType_Issuing,
				Status: pb.IssuerStatus_Active,
				Config: []byte(`{}`),
			},
			{
				ID:     xdb.NewID(1),
				Label:  "trusty.l1",
				Type:   pb.AuthorityType_Intermediate,
				Status: pb.IssuerStatus_Active,
				Config: []byte(`{"AllowedProfiles":["tenant_ca"]}`),
			},
		},
		HasNextPage: true,
		NextOffset:  2,
	}

	// every org and the platform
	caDb.EXPECT().ListIssuers(ctx, gomock.Any()).DoAndReturn(func(_ context.Context, req *query.ListIssuersRequest) (*model.IssuerResult, error) {
		assert.Equal(t, &query.ListIssuersRequest{AllOrgs: true, Status: pb.IssuerStatus_Active, Limit: 10}, req)
		return rows, nil
	})
	res, err := svc.ListIssuers(ctx, &privpb.ListAllIssuersRequest{Status: pb.IssuerStatus_Active, Limit: 10})
	require.NoError(t, err)
	require.Len(t, res.Issuers, 2)
	assert.Equal(t, "100", res.Issuers[0].OrgID)
	assert.Empty(t, res.Issuers[1].OrgID, "a platform issuer has no org")
	assert.Equal(t, []string{"tenant_ca"}, res.Issuers[1].Config.AllowedProfiles)
	require.NotNil(t, res.NextPage)
	assert.Equal(t, 2, int(res.NextPage.Offset))

	// the platform only, by label
	caDb.EXPECT().ListIssuers(ctx, gomock.Any()).DoAndReturn(func(_ context.Context, req *query.ListIssuersRequest) (*model.IssuerResult, error) {
		assert.Equal(t, &query.ListIssuersRequest{Platform: true, Label: "trusty.l1", Limit: 1}, req)
		return &model.IssuerResult{Rows: rows.Rows[1:]}, nil
	})
	res, err = svc.ListIssuers(ctx, &privpb.ListAllIssuersRequest{Platform: true, Label: "trusty.l1", Limit: 1})
	require.NoError(t, err)
	require.Len(t, res.Issuers, 1)
	assert.Nil(t, res.NextPage)

	// an org and its project, by cursor
	cursor := query.EncodeCursor(xdb.NewID(2))
	caDb.EXPECT().ListIssuers(ctx, gomock.Any()).DoAndReturn(func(_ context.Context, req *query.ListIssuersRequest) (*model.IssuerResult, error) {
		assert.Equal(t, uint64(100), req.OrgID)
		assert.Equal(t, uint64(201), req.ProjectID)
		assert.False(t, req.Platform)
		assert.False(t, req.AllOrgs, "the platform flag is ignored with an org")
		assert.Equal(t, pb.AuthorityType_Issuing, req.Type)
		assert.True(t, req.Cursor.IsSet())
		assert.Equal(t, uint64(2), req.Cursor.LastID())
		return &model.IssuerResult{Rows: rows.Rows[:1]}, nil
	})
	res, err = svc.ListIssuers(ctx, &privpb.ListAllIssuersRequest{OrgID: "100", ProjectID: "201", Platform: true, Type: pb.AuthorityType_Issuing, Cursor: cursor})
	require.NoError(t, err)
	require.Len(t, res.Issuers, 1)

	// the requests the service refuses
	for _, tc := range []struct {
		req *privpb.ListAllIssuersRequest
		err string
	}{
		{req: nil, err: "bad_request: missing request"},
		{req: &privpb.ListAllIssuersRequest{OrgID: "nope"}, err: "bad_request: invalid org ID"},
		{req: &privpb.ListAllIssuersRequest{ProjectID: "201"}, err: "bad_request: org ID is required with a project ID"},
		{req: &privpb.ListAllIssuersRequest{OrgID: "100", ProjectID: "nope"}, err: "bad_request: invalid project ID"},
		{req: &privpb.ListAllIssuersRequest{Cursor: "nope"}, err: "bad_request: invalid cursor"},
	} {
		_, err := svc.ListIssuers(ctx, tc.req)
		assert.EqualError(t, err, tc.err)
	}

	caDb.EXPECT().ListIssuers(ctx, gomock.Any()).Return(nil, errors.New("something happened"))
	_, err = svc.ListIssuers(ctx, &privpb.ListAllIssuersRequest{})
	assert.EqualError(t, err, "unexpected: failed to list issuers")

	caDb.EXPECT().ListIssuers(ctx, gomock.Any()).Return(&model.IssuerResult{Rows: []*model.Issuer{{ID: xdb.NewID(3), Config: []byte(`nope`)}}}, nil)
	_, err = svc.ListIssuers(ctx, &privpb.ListAllIssuersRequest{})
	assert.EqualError(t, err, "unexpected: unable to read issuers")
}
