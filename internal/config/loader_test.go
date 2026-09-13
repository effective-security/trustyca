package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cockroachdb/errors"
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
	testDirAbs("Client.ClientTLS.TrustedCAFile", c.Client.ClientTLS.TrustedCAFile)
	testDirAbs("Client.ClientTLS.CertFile", c.Client.ClientTLS.CertFile)
	testDirAbs("Client.ClientTLS.KeyFile", c.Client.ClientTLS.KeyFile)

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
