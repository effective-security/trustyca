package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/client"
	"github.com/effective-security/x/configloader"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

const projFolder = "../../"

func TestConfigFilesAreYAML(t *testing.T) {
	isJSON := func(file string) {
		abs := projFolder + file
		f, err := os.Open(abs)
		require.NoError(t, err, "Unable to open file: %v", file)
		defer f.Close()
		var v map[string]any
		assert.NoError(t, yaml.NewDecoder(f).Decode(&v), "YAML parser error for file %v", file)
	}
	isJSON("etc/dev/" + ConfigFileName)
}

func TestLoadConfig(t *testing.T) {
	_, err := Load("missing.yaml")
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "not found") || os.IsNotExist(err), "LoadConfig with missing file should return a file doesn't exist error: %v", errors.WithStack(err))

	cfgFile, err := configloader.GetAbsFilename("etc/dev/"+ConfigFileName, projFolder)
	require.NoError(t, err, "unable to determine config file")

	c, err := Load(cfgFile)
	require.NoError(t, err, "failed to load config: %v", cfgFile)

	testDirAbs := func(name, dir string) {
		if dir != "" {
			assert.True(t, filepath.IsAbs(dir), "dir %q should be an absoluite path, have: %s", name, dir)
		}
	}
	// the service clients of the dev configuration, by name; their files
	// are expanded to absolute paths
	clients := map[string]client.Config{}
	for _, cl := range c.Clients {
		clients[cl.Name] = cl
	}
	require.Len(t, clients, len(c.Clients), "client names are unique")
	for _, name := range []string{client.ClientNameDefault, client.ClientNameAIA} {
		cl, ok := clients[name]
		require.True(t, ok, "client %s", name)
		testDirAbs("Clients."+name+".ClientTLS.TrustedCAFile", cl.ClientTLS.TrustedCAFile)
		testDirAbs("Clients."+name+".ClientTLS.CertFile", cl.ClientTLS.CertFile)
		testDirAbs("Clients."+name+".ClientTLS.KeyFile", cl.ClientTLS.KeyFile)
		assert.NotEmpty(t, cl.ClientTLS.CertFile, "client %s", name)
	}
	assert.Equal(t, "https://localhost:8881", clients[client.ClientNameAIA].ServerURL[BackendServerName])

	wfe := c.HTTPServers["wfe"]
	require.NotNil(t, wfe)
	require.NotNil(t, wfe.CORS)
}

func TestLoadYAML(t *testing.T) {
	cfgFile, err := configloader.GetAbsFilename("etc/dev/"+ConfigFileName, projFolder)
	require.NoError(t, err, "unable to determine config file")

	f, err := DefaultFactory()
	require.NoError(t, err)

	var c Configuration
	_, err = f.Load(cfgFile, &c)
	require.NoError(t, err, "failed to load config: %v", cfgFile)

	// the CA section and the scheduled tasks of the dev configuration
	assert.Equal(t, 5*time.Minute, c.CA.IssuerCacheTTL)
	assert.Equal(t, 1000, c.CA.IssuerCacheSize)
	assert.Zero(t, c.CA.Retention.ExpiredAfter, "expired certificates are kept")
	require.Len(t, c.Tasks, 2)
	assert.Equal(t, Task{Name: "crl_renewal", Schedule: "every 10 minutes"}, c.Tasks[0])
	assert.Equal(t, Task{Name: "cert_status", Schedule: "every 1 hour"}, c.Tasks[1])
}

func TestLoadYAMLOverrideByHostname(t *testing.T) {
	cfgFile, err := configloader.GetAbsFilename("testdata/test_config.yaml", ".")
	require.NoError(t, err, "unable to determine config file")

	f, err := DefaultFactory()
	require.NoError(t, err)

	os.Setenv("TRUSTYCA_HOSTNAME", "UNIT_TEST")

	var c Configuration
	_, err = f.Load(cfgFile, &c)
	require.NoError(t, err, "failed to load config: %v", cfgFile)
	assert.Equal(t, "UNIT_TEST", c.Service.Environment)
	assert.Equal(t, "local", c.Service.Region)
	assert.Equal(t, "trustyca", c.Service.Name)
	assert.NotEmpty(t, c.Service.ClusterName)

	assert.Len(t, c.LogLevels, 4)
	assert.True(t, c.Metrics.GetDisabled())

	wfe := c.HTTPServers[WFEServerName]
	require.NotNil(t, wfe)
	assert.False(t, wfe.Disabled)
	assert.True(t, wfe.CORS.GetEnabled())
	assert.False(t, wfe.CORS.GetDebug())
	require.NotEmpty(t, c.HTTPServers)

	wfe2 := c.HTTPServers["wfe2"]
	require.NotNil(t, wfe2)
	assert.NotContains(t, wfe2.ServerTLS.CertFile, "$")
	assert.NotContains(t, wfe2.ServerTLS.TrustedCAFile, "$")
}

func TestLoadYAMLWithOverride(t *testing.T) {
	cfgFile, err := configloader.GetAbsFilename("testdata/test_config.yaml", ".")
	require.NoError(t, err, "unable to determine config file")
	cfgOverrideFile, err := configloader.GetAbsFilename("testdata/test_config-override.yaml", ".")
	require.NoError(t, err, "unable to determine config file")

	f, err := DefaultFactory()
	require.NoError(t, err)

	f.WithOverride(cfgOverrideFile)

	os.Setenv("TRUSTYCA_HOSTNAME", "UNIT_TEST")

	var c Configuration
	_, err = f.Load(cfgFile, &c)
	require.NoError(t, err, "failed to load config: %v", cfgFile)
	assert.Equal(t, "UNIT_TEST", c.Service.Environment)
	assert.Equal(t, "local", c.Service.Region)
	assert.Equal(t, "trustyca", c.Service.Name)
	assert.NotEmpty(t, c.Service.ClusterName)

	assert.Len(t, c.LogLevels, 4)

	wfe := c.HTTPServers[WFEServerName]
	require.NotNil(t, wfe)
	assert.False(t, wfe.Disabled)
	assert.True(t, wfe.CORS.GetEnabled())
	assert.False(t, wfe.CORS.GetDebug())
	require.NotEmpty(t, c.HTTPServers)

	assert.True(t, c.Metrics.GetDisabled())
}
