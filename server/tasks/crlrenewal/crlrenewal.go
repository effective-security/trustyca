package crlrenewal

import (
	"context"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/pkg/tasks"
	"github.com/effective-security/porto/xhttp/correlation"
	"github.com/effective-security/trustyca/api/pb"
	core "github.com/effective-security/trustyca/internal/ca"
	"github.com/effective-security/trustyca/internal/db"
	"github.com/effective-security/trustyca/internal/events"
	"github.com/effective-security/trustyca/internal/metricskey"
	"github.com/effective-security/xlog"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/trustyca/server/tasks", "crlrenewal")

// TaskName is the name of the task in the tasks configuration
const TaskName = "crl_renewal"

// Task publishes the CRLs that are due
type Task struct {
	name      string
	schedule  string
	publisher *core.CrlPublisher
	events    events.Recorder
}

// New returns the task over the publisher; the recorder stores the
// CrlPublished events
func New(name, schedule string, publisher *core.CrlPublisher, recorder events.Recorder) *Task {
	return &Task{
		name:      name,
		schedule:  schedule,
		publisher: publisher,
		events:    recorder,
	}
}

// Run publishes the due CRLs of every org and the platform once, under a
// new correlation ID, and returns the outcome; a failure to list the
// issuers is logged and returned, after the events of the CRLs published
// before it
func (t *Task) Run(ctx context.Context) (*core.PublishCrlsResult, error) {
	ctx = correlation.WithID(ctx)
	defer metricskey.PerfTaskRun.MeasureSince(time.Now(), TaskName)

	res, err := t.publisher.PublishCrls(ctx, &core.PublishCrlsRequest{AllOrgs: true})
	for _, crl := range res.Crls {
		events.New(ctx, TaskName, pb.EventType_CrlPublished, "CRL published").
			Org(crl.OrgID).
			Project(crl.ProjectID).
			Reference(crl.ID).
			Description("CRL %d of issuer %q published", crl.CrlNumber, crl.Issuer).
			Emit(t.events)
	}
	if err != nil {
		logger.ContextKV(ctx, xlog.ERROR,
			"task", TaskName,
			"reason", "publish_crls",
			"published", len(res.Crls),
			"err", err.Error())
		return res, err
	}
	logger.ContextKV(ctx, xlog.INFO,
		"task", TaskName,
		"published", len(res.Crls),
		"skipped", res.Skipped,
		"failed", res.Failed)
	return res, nil
}

// run is the scheduled callback
func (t *Task) run() {
	_, _ = t.Run(context.Background())
}

// Factory returns the task factory: the function it returns is invoked by
// the application container with the CA DB, the orgs DB that records the
// events and the issuer registry, schedules the task and runs it at once
func Factory(
	s tasks.Scheduler,
	name string,
	schedule string,
	args ...string,
) any {
	return func(caDb db.CaDb, orgsDb db.OrgsDb, registry *core.Registry) error {
		task := New(name, schedule, core.NewCrlPublisher(caDb, registry), orgsDb)
		job, err := tasks.NewTask(task.schedule)
		if err != nil {
			return errors.WithMessagef(err, "unable to schedule task %q: %s", task.name, task.schedule)
		}
		t := job.Do(task.name, task.run)
		s.Add(t)
		// serve CRLs at once, without waiting for the first tick
		go t.Run()
		return nil
	}
}
