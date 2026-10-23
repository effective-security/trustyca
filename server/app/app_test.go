package app

import (
	"os"
	"path"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/internal/config"
	"github.com/effective-security/trustyca/tests/testutils"
	"github.com/effective-security/x/configloader"
	"github.com/effective-security/x/guid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const projFolder = "../../"

var (
	testDirPath = filepath.Join(os.TempDir(), "tests", "trustyca", guid.MustCreate())
)

func TestMain(m *testing.M) {
	_ = os.MkdirAll(testDirPath, 0700)
	defer os.RemoveAll(testDirPath)

	// ensure task are not started
	os.Setenv("TRUSTYCA_HOSTNAME", "UNIT_TEST")

	// Run the tests
	rc := m.Run()
	os.Exit(rc)
}

func Test_App_NoConfig(t *testing.T) {
	app := NewApp([]string{"--dry-run"})
	defer app.Close()

	err := app.Run(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load configuration: file \"trustyca-config.yaml\" not found in")
}

func Test_AppOnClose(t *testing.T) {
	cfgFile, err := configloader.GetAbsFilename("etc/dev/"+config.ConfigFileName, projFolder)
	require.NoError(t, err, "unable to determine config file")

	c := &closer{}
	app := NewApp([]string{
		"--log-std",
		"--cfg", cfgFile,
		"--wfe-listen-url", testutils.CreateURL("http", "localhost"),
		"--backend-listen-url", testutils.CreateURL("http", "localhost"),
		"--aia-listen-url", testutils.CreateURL("http", "localhost"),
	})

	app.OnClose(c)
	assert.False(t, c.closed)

	err = app.loadConfig()
	require.NoError(t, err)

	err = app.Close()
	require.NoError(t, err)

	assert.True(t, c.closed)

	err = app.Close()
	require.Error(t, err)
	assert.Equal(t, "already closed", err.Error())
}

// Test_App_ClientCertFlags checks that the single client certificate flags
// of porto are refused: a process dials with the named clients of the
// configuration, each with its own certificate
func Test_App_ClientCertFlags(t *testing.T) {
	cfgFile, err := configloader.GetAbsFilename("etc/dev/"+config.ConfigFileName, projFolder)
	require.NoError(t, err, "unable to determine config file")

	for _, flag := range []string{"--client-cert", "--client-key", "--client-trusted-ca"} {
		app := NewApp([]string{
			"--dry-run",
			"--cfg", cfgFile,
			flag, "/tmp/client.pem",
		})
		err = app.loadConfig()
		assert.EqualError(t, err, "--client-cert, --client-key and --client-trusted-ca are not supported: set client_tls of the clients in the configuration", flag)
		require.NoError(t, app.Close())
	}
}

func Test_AppInitWithRun(t *testing.T) {
	cfgFile, err := configloader.GetAbsFilename("etc/dev/"+config.ConfigFileName, projFolder)
	require.NoError(t, err, "unable to determine config file")

	c := &closer{}
	app := NewApp([]string{
		"--dry-run",
		"--cfg", cfgFile,
		"--wfe-listen-url", testutils.CreateURL("http", "localhost"),
		"--backend-listen-url", testutils.CreateURL("http", "localhost"),
		"--aia-listen-url", testutils.CreateURL("http", "localhost"),
	})

	err = app.Run(nil)
	assert.NoError(t, err)

	defer app.OnClose(c)
}

func Test_AppInitWithCfg(t *testing.T) {
	cfgFile, err := configloader.GetAbsFilename("etc/dev/"+config.ConfigFileName, projFolder)
	require.NoError(t, err, "unable to determine config file")

	cpuf := path.Join(testDirPath, "profiler")
	defer os.Remove(cpuf)

	c := &closer{}
	app := NewApp([]string{
		"--dry-run",
		"--cfg", cfgFile,
		"--wfe-listen-url", testutils.CreateURL("http", "localhost"),
		"--backend-listen-url", testutils.CreateURL("http", "localhost"),
		"--aia-listen-url", testutils.CreateURL("http", "localhost"),
	})
	defer app.OnClose(c)

	err = app.loadConfig()
	require.NoError(t, err)

	_, err = app.containerFactory()
	require.NoError(t, err)
}

func Test_AppInstance_StartStop(t *testing.T) {
	// the platform issuer the start bootstraps into the dev DB is wrapped
	// under the seed of the environment, and a key wrapped under another
	// seed fails the start
	testutils.SetDataProtectionSeed(t)
	cfgPath, err := filepath.Abs(projFolder + "etc/dev/" + config.ConfigFileName)
	require.NoError(t, err)

	sigs := make(chan os.Signal, 2)
	app := NewApp([]string{
		"--log-std",
		"--cfg", cfgPath,
		"--wfe-listen-url", testutils.CreateURL("http", "localhost"),
		"--backend-listen-url", testutils.CreateURL("http", "localhost"),
		"--aia-listen-url", testutils.CreateURL("http", "localhost"),
	}).WithSignal(sigs)
	defer app.Close()

	var wg sync.WaitGroup
	startedCh := make(chan bool)

	var expError error
	wg.Add(1)
	go func() {
		defer wg.Done()

		expError = app.Run(startedCh)
		if expError != nil {
			t.Log(expError.Error())
			startedCh <- false
		}
	}()

	// wait for start
	select {
	case ret := <-startedCh:
		if assert.True(t, ret, "server NOT started") {
			t.Log("server started")
			// trigger stop
			sigs <- syscall.SIGUSR2
			sigs <- syscall.SIGTERM
			t.Log("server stopping...")
		}

	case <-time.After(10 * time.Second):
		t.Log("failed to start")
		require.True(t, false, "failed to start")
		break
	}

	// wait for stop
	wg.Wait()

	require.NoError(t, expError)
}

// Test_AppInstance_WebRole starts the listeners of a web pod (DESIGN.md
// section 2.2) under a configuration whose crypto provider and platform
// bootstrap do not exist: the wfe and aia listeners start, because only the
// backend service and the crl_renewal task build the issuer registry,
// while a process that runs the backend service fails to start on them
func Test_AppInstance_WebRole(t *testing.T) {
	testutils.SetDataProtectionSeed(t)
	cfgPath, err := filepath.Abs(projFolder + "etc/dev/" + config.ConfigFileName)
	require.NoError(t, err)
	override := filepath.Join(t.TempDir(), "web-role.yaml")
	require.NoError(t, os.WriteFile(override, []byte(`
metrics:
  disabled: true
tasks: []
crypto_provider:
  default: /nonexistent/trustyca/kms.yaml
ca:
  bootstrap_config: /nonexistent/trustyca/ca-config.yaml
`), 0o600))

	start := func(backendURL string) error {
		sigs := make(chan os.Signal, 2)
		app := NewApp([]string{
			"--log-std",
			"--cfg", cfgPath,
			"--cfg-override", override,
			"--wfe-listen-url", testutils.CreateURL("http", "localhost"),
			"--backend-listen-url", backendURL,
			"--aia-listen-url", testutils.CreateURL("http", "localhost"),
		}).WithSignal(sigs)
		defer app.Close()

		startedCh := make(chan bool, 1)
		errCh := make(chan error, 1)
		go func() {
			errCh <- app.Run(startedCh)
		}()
		select {
		case <-startedCh:
			sigs <- syscall.SIGTERM
			return <-errCh
		case err := <-errCh:
			return err
		case <-time.After(10 * time.Second):
			return errors.New("timeout")
		}
	}

	// a web pod: wfe and aia, no backend
	require.NoError(t, start("none"))

	// a signing pod needs its crypto provider
	err = start(testutils.CreateURL("http", "localhost"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "/nonexistent/trustyca/")
}

type closer struct {
	closed bool
}

func (c *closer) Close() error {
	if c.closed {
		return errors.New("already closed")
	}
	c.closed = true
	return nil
}
