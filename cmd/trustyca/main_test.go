package main

import (
	"bytes"
	"testing"

	"github.com/effective-security/trustyca/api/version"
	"github.com/stretchr/testify/assert"
)

func TestMain(t *testing.T) {
	out := bytes.NewBuffer([]byte{})
	errout := bytes.NewBuffer([]byte{})
	rc := 0
	exit := func(c int) {
		rc = c
	}

	realMain([]string{"trustyca", "--version"}, out, errout, exit)
	assert.Equal(t, version.Current().String()+"\n", out.String())
	// since our exit func does not call os.Exit, the next parser will fail
	assert.Equal(t, 80, rc)
	assert.NotEmpty(t, errout.String())
}

// TestHelp parses the whole command tree: a flag or help text kong refuses
// panics at startup, not in a test of a command
func TestHelp(t *testing.T) {
	var out, errout bytes.Buffer
	// kong calls exit after the help; the function records the first code
	// and returns, so the parser then reports the missing command
	exitCode := -1
	realMain([]string{"trustyca", "--help"}, &out, &errout, func(code int) {
		if exitCode == -1 {
			exitCode = code
		}
	})
	assert.Equal(t, 0, exitCode)
	assert.Contains(t, out.String(), "cert status")
}
