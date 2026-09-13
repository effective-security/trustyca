package main

import (
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
