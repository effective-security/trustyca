package testutils

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/tests/testutils"
	"github.com/effective-security/trustyca/internal/config"
	"github.com/effective-security/x/configloader"
	"github.com/effective-security/x/fileutil/resolve"
	"github.com/effective-security/x/netutil"
	"github.com/effective-security/xlog"
	"github.com/stretchr/testify/assert"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/trustyca", "testutils")

// LoadConfig returns Configuration
func LoadConfig(hostname string) (*config.Configuration, error) {
	if hostname != "" {
		os.Setenv("TRUSTYCA_HOSTNAME", hostname)
	}

	oscwd, _ := os.Getwd()
	_, caller, _, _ := runtime.Caller(1)
	argscwd, _ := filepath.Abs(filepath.Dir(os.Args[0]))

	// try the list of allowed locations to find the config file
	searchDirs := []string{
		argscwd,
		argscwd + "/etc/dev",
		oscwd + "/etc/dev",
		oscwd + "/../etc/dev",
		oscwd + "/../../etc/dev",
		oscwd + "/../../../etc/dev",
		oscwd + "/../../../../etc/dev",
		filepath.Dir(caller) + "/etc/dev",
	}

	f, err := configloader.NewFactory(nil, searchDirs, "TRUSTYCA_")
	if err != nil {
		return nil, err
	}

	cfg := new(config.Configuration)
	_, err = f.LoadForHostName(config.ConfigFileName, hostname, cfg)
	if err != nil {
		//logger.KV(xlog.ERROR, "cwd", oscwd, "caller", caller, "args", argscwd)
		return nil, err
	}

	return cfg, nil
}

func ResolveConfigFile(configFile string, searchDirs []string) (absConfigFile, baseDir string, err error) {
	if configFile == "" {
		panic("config file not provided!")
		//configFile = ConfigFileName
	}

	if filepath.IsAbs(configFile) {
		// for absolute, use the folder containing the config file
		baseDir = filepath.Dir(configFile)
		absConfigFile = configFile
		return
	}

	for _, absDir := range searchDirs {
		absConfigFile, err = resolve.File(configFile, absDir)
		if err == nil && absConfigFile != "" {
			baseDir = absDir
			logger.KV(xlog.DEBUG, "resolved", absConfigFile)
			return
		}
	}

	err = errors.Errorf("file %q not found in [%s]", configFile, strings.Join(searchDirs, ","))
	return
}

// CreateURL returns URL with a random port
func CreateURL(scheme, host string) string {
	bind := testutils.CreateBindAddr(host)

	return fmt.Sprintf("%s://%s", scheme, bind)
}

var usedPorts = map[int]bool{}

func findFreePort(host string, maxAttempts int) int {
	for i := 0; i < maxAttempts; i++ {
		port, err := netutil.FindFreePort(host, 5)
		if err != nil {
			panic("unable to find free port: " + err.Error())
		}
		if usedPorts[port] {
			continue
		}
		usedPorts[port] = true
		return port
	}
	panic("unable to find free port")
}

// CreateURLs returns list of URL with a random port
func CreateURLs(scheme, host string, len int) []string {
	list := make([]string, len)
	port := findFreePort(host, 5)
	for i := 0; i < len; i++ {
		if usedPorts[port] {
			port = findFreePort(host, 5)
		}
		list[i] = fmt.Sprintf("%s://%s:%d", scheme, host, port)
		logger.KV(xlog.DEBUG, "allocated", list[i])
		port++
	}
	return list
}

// CreateBindAddr returns a bind address with a random port
func CreateBindAddr(host string) string {
	port, err := netutil.FindFreePort(host, 5)
	if err != nil {
		panic("unable to find free port: " + err.Error())
	}

	return fmt.Sprintf("%s:%d", host, port)
}

// JSON returns json string
func JSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func JSONIndent(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

// CompareJSON asserts that JSON encodings are the same
func CompareJSON(t *testing.T, a, b any) {
	t.Helper()
	assert.Equal(t, JSON(a), JSON(b))
}
