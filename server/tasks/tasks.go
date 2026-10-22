package tasks

import (
	"github.com/effective-security/porto/pkg/tasks"
	"github.com/effective-security/trustyca/server/tasks/certstatus"
	"github.com/effective-security/trustyca/server/tasks/crlrenewal"
)

// Status indicates whether the task failed or succeeded
type Status int

const (
	// FAILURE indicates that the task failed
	FAILURE Status = 0

	// SUCCESS indicates that the task succeeded
	SUCCESS Status = 1
)

// Factory creates tasks: it returns the function the application
// container invokes with the dependencies of the task
type Factory func(
	scheduler tasks.Scheduler,
	name string,
	schedule string,
	args ...string,
) any

// Factories provides map of Factory by task name
var Factories = map[string]Factory{
	crlrenewal.TaskName: crlrenewal.Factory,
	certstatus.TaskName: certstatus.Factory,
}
