package tasks_test

import (
	"testing"

	"github.com/effective-security/trustyca/server/tasks"
	"github.com/effective-security/trustyca/server/tasks/certstatus"
	"github.com/effective-security/trustyca/server/tasks/crlrenewal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Factories(t *testing.T) {
	assert.Len(t, tasks.Factories, 2)
	for _, name := range []string{crlrenewal.TaskName, certstatus.TaskName} {
		f := tasks.Factories[name]
		require.NotNil(t, f, name)
		fact := f(nil, "", "")
		require.NotNil(t, fact, name)
	}
	assert.Nil(t, tasks.Factories["unknown"])
}
