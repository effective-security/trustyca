package certstatus_test

import (
	"context"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/pkg/tasks"
	"github.com/effective-security/trustyca/internal/config"
	"github.com/effective-security/trustyca/internal/db"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/mocks/mocktrustycadb"
	"github.com/effective-security/trustyca/server/tasks/certstatus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestTask_Run(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	cadb := mocktrustycadb.NewMockCaDb(ctrl)
	ctx := context.Background()
	now := time.Now()
	const retention = 30 * 24 * time.Hour

	// the batches continue until one is not full; without a retention
	// nothing is deleted
	gomock.InOrder(
		cadb.EXPECT().ExpireCertificates(gomock.Any(), gomock.Any()).DoAndReturn(
			func(_ context.Context, req *query.ExpireCertificatesRequest) (int64, error) {
				assert.EqualValues(t, certstatus.BatchSize, req.Limit)
				assert.WithinDuration(t, now, req.Before, time.Minute)
				return certstatus.BatchSize, nil
			}),
		cadb.EXPECT().ExpireCertificates(gomock.Any(), gomock.Any()).Return(int64(3), nil),
	)
	task := certstatus.New(certstatus.TaskName, "every 1 hour", cadb, 0)
	res, err := task.Run(ctx)
	require.NoError(t, err)
	assert.EqualValues(t, certstatus.BatchSize+3, res.Expired)
	assert.Zero(t, res.Deleted)

	// the retention deletes the certificates expired before now minus the
	// period
	gomock.InOrder(
		cadb.EXPECT().ExpireCertificates(gomock.Any(), gomock.Any()).Return(int64(0), nil),
		cadb.EXPECT().DeleteExpiredCertificates(gomock.Any(), gomock.Any()).DoAndReturn(
			func(_ context.Context, req *query.DeleteExpiredCertificatesRequest) (int64, error) {
				assert.EqualValues(t, certstatus.BatchSize, req.Limit)
				assert.WithinDuration(t, now.Add(-retention), req.Before, time.Minute)
				return 2, nil
			}),
	)
	retained := certstatus.New(certstatus.TaskName, "every 1 hour", cadb, retention)
	res, err = retained.Run(ctx)
	require.NoError(t, err)
	assert.Zero(t, res.Expired)
	assert.EqualValues(t, 2, res.Deleted)

	// failures are returned with the counts so far
	cadb.EXPECT().ExpireCertificates(gomock.Any(), gomock.Any()).Return(int64(0), errors.New("db down"))
	_, err = retained.Run(ctx)
	assert.EqualError(t, err, "db down")
	gomock.InOrder(
		cadb.EXPECT().ExpireCertificates(gomock.Any(), gomock.Any()).Return(int64(1), nil),
		cadb.EXPECT().DeleteExpiredCertificates(gomock.Any(), gomock.Any()).Return(int64(0), errors.New("db down")),
	)
	res, err = retained.Run(ctx)
	assert.EqualError(t, err, "db down")
	assert.EqualValues(t, 1, res.Expired)

	// a run is bounded by the number of batches
	cadb.EXPECT().ExpireCertificates(gomock.Any(), gomock.Any()).Return(int64(certstatus.BatchSize), nil).Times(certstatus.MaxBatches)
	res, err = task.Run(ctx)
	require.NoError(t, err)
	assert.EqualValues(t, certstatus.BatchSize*certstatus.MaxBatches, res.Expired)
}

func TestFactory(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	cadb := mocktrustycadb.NewMockCaDb(ctrl)
	cadb.EXPECT().ExpireCertificates(gomock.Any(), gomock.Any()).Return(int64(0), nil).AnyTimes()
	cadb.EXPECT().DeleteExpiredCertificates(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, req *query.DeleteExpiredCertificatesRequest) (int64, error) {
			assert.WithinDuration(t, time.Now().Add(-time.Hour), req.Before, time.Minute, "the retention of the configuration")
			return 0, nil
		}).AnyTimes()
	cfg := &config.Configuration{}
	cfg.CA.Retention.ExpiredAfter = time.Hour
	scheduler := tasks.NewScheduler()

	fact, ok := certstatus.Factory(scheduler, certstatus.TaskName, "every 1 hour").(func(*config.Configuration, db.CaDb) error)
	require.True(t, ok)
	require.NoError(t, fact(cfg, cadb))
	require.Equal(t, 1, scheduler.Count())
	// the task runs at once when scheduled
	require.Eventually(t, func() bool {
		list := scheduler.List()
		return len(list) == 1 && list[0].RunCount() == 1 && !list[0].IsRunning()
	}, 10*time.Second, 10*time.Millisecond)

	bad, ok := certstatus.Factory(scheduler, certstatus.TaskName, "never").(func(*config.Configuration, db.CaDb) error)
	require.True(t, ok)
	err := bad(cfg, cadb)
	assert.ErrorContains(t, err, `unable to schedule task "cert_status": never`)
	assert.Equal(t, 1, scheduler.Count())
}
