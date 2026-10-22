package certstatus

import (
	"context"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/pkg/tasks"
	"github.com/effective-security/porto/xhttp/correlation"
	"github.com/effective-security/trustyca/internal/config"
	"github.com/effective-security/trustyca/internal/db"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/internal/metricskey"
	"github.com/effective-security/xlog"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/trustyca/server/tasks", "certstatus")

// TaskName is the name of the task in the tasks configuration
const TaskName = "cert_status"

const (
	// BatchSize is the number of certificates one statement changes
	BatchSize = 1000
	// MaxBatches bounds the statements of one run; the next run continues
	MaxBatches = 1000
)

// Task marks expired certificates and applies the retention
type Task struct {
	name      string
	schedule  string
	db        db.CaDb
	retention time.Duration
}

// Result counts the certificates a run changed
type Result struct {
	// Expired is the number of certificates marked Expired
	Expired int64
	// Deleted is the number of certificates deleted by the retention
	Deleted int64
}

// New returns the task over the CA DB; a zero retention keeps expired
// certificates forever
func New(name, schedule string, caDb db.CaDb, retention time.Duration) *Task {
	return &Task{
		name:      name,
		schedule:  schedule,
		db:        caDb,
		retention: retention,
	}
}

// Run marks the certificates that expired before now and deletes those
// that expired before now minus the retention, under a new correlation ID,
// and returns the counts; a DB failure is logged and returned with the
// counts so far
func (t *Task) Run(ctx context.Context) (*Result, error) {
	ctx = correlation.WithID(ctx)
	defer metricskey.PerfTaskRun.MeasureSince(time.Now(), TaskName)
	now := time.Now()
	res := &Result{}

	var err error
	res.Expired, err = batches(ctx, func(ctx context.Context) (int64, error) {
		return t.db.ExpireCertificates(ctx, &query.ExpireCertificatesRequest{
			Before: now,
			Limit:  BatchSize,
		})
	})
	if err != nil {
		logger.ContextKV(ctx, xlog.ERROR,
			"task", TaskName,
			"reason", "expire_certificates",
			"expired", res.Expired,
			"err", err.Error())
		return res, err
	}
	if t.retention > 0 {
		cutoff := now.Add(-t.retention)
		res.Deleted, err = batches(ctx, func(ctx context.Context) (int64, error) {
			return t.db.DeleteExpiredCertificates(ctx, &query.DeleteExpiredCertificatesRequest{
				Before: cutoff,
				Limit:  BatchSize,
			})
		})
		if err != nil {
			logger.ContextKV(ctx, xlog.ERROR,
				"task", TaskName,
				"reason", "delete_expired_certificates",
				"expired", res.Expired,
				"deleted", res.Deleted,
				"err", err.Error())
			return res, err
		}
	}
	logger.ContextKV(ctx, xlog.INFO,
		"task", TaskName,
		"expired", res.Expired,
		"deleted", res.Deleted)
	return res, nil
}

// batches repeats the statement until a batch is smaller than BatchSize,
// at most MaxBatches times, and returns the rows it changed
func batches(ctx context.Context, stmt func(ctx context.Context) (int64, error)) (int64, error) {
	var total int64
	for range MaxBatches {
		n, err := stmt(ctx)
		if err != nil {
			return total, err
		}
		total += n
		if n < BatchSize {
			return total, nil
		}
	}
	logger.ContextKV(ctx, xlog.WARNING,
		"task", TaskName,
		"reason", "batch_limit",
		"rows", total)
	return total, nil
}

// run is the scheduled callback
func (t *Task) run() {
	_, _ = t.Run(context.Background())
}

// Factory returns the task factory: the function it returns is invoked by
// the application container with the configuration and the CA DB,
// schedules the task and runs it at once
func Factory(
	s tasks.Scheduler,
	name string,
	schedule string,
	args ...string,
) any {
	return func(cfg *config.Configuration, caDb db.CaDb) error {
		task := New(name, schedule, caDb, cfg.CA.Retention.ExpiredAfter)
		job, err := tasks.NewTask(task.schedule)
		if err != nil {
			return errors.WithMessagef(err, "unable to schedule task %q: %s", task.name, task.schedule)
		}
		t := job.Do(task.name, task.run)
		s.Add(t)
		go t.Run()
		return nil
	}
}
