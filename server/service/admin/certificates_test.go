package admin

import (
	"context"
	"testing"
	"time"

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

func TestService_ListCertificates(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	caDb := mocktrustycadb.NewMockCaReadonlyDb(ctrl)
	svc := Service{
		ca: caDb,
	}
	rows := &model.CertificateResult{
		Rows: []*model.Certificate{
			{
				ID:        xdb.NewID(2),
				OrgID:     xdb.NewID(100),
				ProjectID: xdb.NewID(201),
				Ikid:      "ikid-1",
				Profile:   "server",
				Status:    pb.CertificateStatus_Active,
				Label:     "edge-1",
			},
			{
				ID:     xdb.NewID(1),
				Ikid:   "ikid-0",
				Status: pb.CertificateStatus_Revoked,
			},
		},
		HasNextPage: true,
		NextOffset:  2,
	}

	// every org and the platform
	caDb.EXPECT().ListCertificates(ctx, gomock.Any()).DoAndReturn(func(_ context.Context, req *query.ListCertificatesRequest) (*model.CertificateResult, error) {
		assert.Equal(t, &query.ListCertificatesRequest{AllOrgs: true, Limit: 10}, req)
		return rows, nil
	})
	res, err := svc.ListCertificates(ctx, &privpb.ListCertificatesRequest{Limit: 10})
	require.NoError(t, err)
	require.Len(t, res.Certificates, 2)
	assert.Equal(t, "100", res.Certificates[0].OrgID)
	assert.Equal(t, "201", res.Certificates[0].ProjectID)
	assert.Equal(t, "edge-1", res.Certificates[0].Label, "the support view keeps the client fields")
	assert.Empty(t, res.Certificates[1].OrgID, "a platform certificate has no org")
	require.NotNil(t, res.NextPage)
	assert.Equal(t, 2, int(res.NextPage.Offset))

	// an org, by issuer, profile, status and expiry
	expiring := time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)
	caDb.EXPECT().ListCertificates(ctx, gomock.Any()).DoAndReturn(func(_ context.Context, req *query.ListCertificatesRequest) (*model.CertificateResult, error) {
		assert.Equal(t, &query.ListCertificatesRequest{
			OrgID:          100,
			IKID:           "ikid-1",
			Profile:        "server",
			Status:         pb.CertificateStatus_Active,
			ExpiringBefore: &expiring,
			Limit:          5,
			Offset:         10,
		}, req)
		return &model.CertificateResult{Rows: rows.Rows[:1]}, nil
	})
	res, err = svc.ListCertificates(ctx, &privpb.ListCertificatesRequest{
		OrgID:          "100",
		IKID:           "ikid-1",
		Profile:        "server",
		Status:         pb.CertificateStatus_Active,
		ExpiringBefore: "2027-01-02T04:04:05+01:00",
		Limit:          5,
		Offset:         10,
	})
	require.NoError(t, err)
	require.Len(t, res.Certificates, 1)
	assert.Nil(t, res.NextPage)

	// the platform only
	caDb.EXPECT().ListCertificates(ctx, gomock.Any()).DoAndReturn(func(_ context.Context, req *query.ListCertificatesRequest) (*model.CertificateResult, error) {
		assert.True(t, req.Platform)
		assert.False(t, req.AllOrgs)
		return &model.CertificateResult{}, nil
	})
	res, err = svc.ListCertificates(ctx, &privpb.ListCertificatesRequest{Platform: true})
	require.NoError(t, err)
	assert.Empty(t, res.Certificates)

	// the requests the service refuses
	for _, tc := range []struct {
		req *privpb.ListCertificatesRequest
		err string
	}{
		{req: nil, err: "bad_request: missing request"},
		{req: &privpb.ListCertificatesRequest{OrgID: "nope"}, err: "bad_request: invalid org ID"},
		{req: &privpb.ListCertificatesRequest{ProjectID: "201"}, err: "bad_request: org ID is required with a project ID"},
		{req: &privpb.ListCertificatesRequest{Cursor: "nope"}, err: "bad_request: invalid cursor"},
		{req: &privpb.ListCertificatesRequest{ExpiringBefore: "tomorrow"}, err: "bad_request: invalid ExpiringBefore: RFC3339 time expected"},
	} {
		_, err := svc.ListCertificates(ctx, tc.req)
		assert.EqualError(t, err, tc.err)
	}

	caDb.EXPECT().ListCertificates(ctx, gomock.Any()).Return(nil, errors.New("something happened"))
	_, err = svc.ListCertificates(ctx, &privpb.ListCertificatesRequest{})
	assert.EqualError(t, err, "unexpected: failed to list certificates")
}
