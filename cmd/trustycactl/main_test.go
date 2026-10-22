package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/effective-security/trustyca/api/version"
	"github.com/effective-security/x/guid"
	"github.com/stretchr/testify/assert"
)

var testDirPath = filepath.Join(os.TempDir(), "/tests/trustyca/cmd", "trustyca-"+guid.MustCreate())

func TestMain(m *testing.M) {
	//_ = os.MkdirAll(testDirPath, 0700)
	//defer os.RemoveAll(testDirPath)

	// Run the tests
	rc := m.Run()
	os.Exit(rc)
}

func TestGoVersion(t *testing.T) {
	gv := runtime.Version()
	vsCheck := strings.HasPrefix(gv, "go1.26") || strings.HasPrefix(gv, "go1.27")
	assert.True(t, vsCheck, "should be built with go 1.26.+, got: %s", gv)
}

func TestVersion(t *testing.T) {
	gv := version.Current()
	assert.True(t, gv.Float() > 0)
	assert.NotEmpty(t, gv.Runtime)
}

// TestHelp parses the whole command tree: a flag or help text kong refuses
// panics at startup, not in a test of a command
func TestHelp(t *testing.T) {
	var out, errout bytes.Buffer
	// kong calls exit after the help; the function records the first code
	// and returns, so the parser then reports the missing command
	exitCode := -1
	realMain([]string{"trustycactl", "--help"}, &out, &errout, func(code int) {
		if exitCode == -1 {
			exitCode = code
		}
	})
	assert.Equal(t, 0, exitCode)
	assert.Contains(t, out.String(), "ca issuer list")
}
