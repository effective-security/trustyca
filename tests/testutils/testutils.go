package testutils

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/internal/config"
	"github.com/effective-security/x/configloader"
	"github.com/effective-security/x/fileutil/resolve"
	"github.com/effective-security/x/netutil"
	"github.com/effective-security/xlog"
	"github.com/stretchr/testify/assert"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/trustyca", "testutils")

// DataProtectionSeedEnv is the environment variable of the data protection
// seed every process that uses the dev database must share
const DataProtectionSeedEnv = "TRUSTYCA_DP_SEED"

// DefaultDataProtectionSeed is the seed of the Makefile, used when the
// environment sets none (CI)
const DefaultDataProtectionSeed = "testseed"

// SetDataProtectionSeed pins the data protection seed of a test that builds
// the app container against the dev database: the environment's seed when
// it sets one, so that the test agrees with a server started from the same
// shell or IDE, else DefaultDataProtectionSeed. It uses t.Setenv, so the
// test must not be parallel. The platform issuer bootstrapped into the dev
// database is wrapped under the seed of the first process that registered
// it; a process with another seed fails the start.
func SetDataProtectionSeed(t testing.TB) {
	t.Helper()
	seed := os.Getenv(DataProtectionSeedEnv)
	if seed == "" {
		seed = DefaultDataProtectionSeed
	}
	t.Setenv(DataProtectionSeedEnv, seed)
}

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

// portAttempts bounds how many probed ports reservePort tries before it
// gives up on finding one this process has not handed out yet.
const portAttempts = 10

// reservedPorts records every port CreateURL, CreateURLs and CreateBindAddr
// handed out in this process, so that parallel tests never get the same
// one. It cannot reserve a port at the OS: another process may bind it
// after the probe listener closes.
var reservedPorts = struct {
	sync.Mutex
	ports map[int]struct{}
}{ports: map[int]struct{}{}}

// reservePort probes for a free port on host that this process has not
// handed out yet, and records it. It panics when none is found.
func reservePort(host string) int {
	for range portAttempts {
		port, err := netutil.FindFreePort(host, 5)
		if err != nil {
			panic("unable to find free port: " + err.Error())
		}
		reservedPorts.Lock()
		_, used := reservedPorts.ports[port]
		if !used {
			reservedPorts.ports[port] = struct{}{}
		}
		reservedPorts.Unlock()
		if !used {
			return port
		}
	}
	panic("unable to find free port")
}

// CreateURL returns a URL with a free port on host that no other caller
// in this process got
func CreateURL(scheme, host string) string {
	return fmt.Sprintf("%s://%s", scheme, CreateBindAddr(host))
}

// CreateURLs returns count URLs, each with its own free port on host that
// no other caller in this process got
func CreateURLs(scheme, host string, count int) []string {
	list := make([]string, count)
	for i := range list {
		list[i] = fmt.Sprintf("%s://%s", scheme, CreateBindAddr(host))
		logger.KV(xlog.DEBUG, "allocated", list[i])
	}
	return list
}

// CreateBindAddr returns a bind address with a free port on host that no
// other caller in this process got
func CreateBindAddr(host string) string {
	return net.JoinHostPort(host, strconv.Itoa(reservePort(host)))
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
