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
	for _, name := range []string{client.ClientNameCA, client.ClientNameAIA} {
		cl, ok := clients[name]
		require.True(t, ok, "client %s", name)
		testDirAbs("Clients."+name+".ClientTLS.TrustedCAFile", cl.ClientTLS.TrustedCAFile)
		testDirAbs("Clients."+name+".ClientTLS.CertFile", cl.ClientTLS.CertFile)
		testDirAbs("Clients."+name+".ClientTLS.KeyFile", cl.ClientTLS.KeyFile)
		assert.NotEmpty(t, cl.ClientTLS.CertFile, "client %s", name)
	}
	assert.Equal(t, "https://localhost:8881", clients[client.ClientNameAIA].ServerURL[BackendServerName])

	// the dev instance offers the local identity provider
	assert.True(t, c.Service.IsLocal())

	wfe := c.HTTPServers["wfe"]
	require.NotNil(t, wfe)
	require.NotNil(t, wfe.CORS)
	require.NoError(t, wfe.CORS.Validate())
	// the console in bearer mode, and in cookie mode on a host under the
	// cookie domain
	assert.Contains(t, wfe.CORS.AllowedOrigins, "http://localhost:4200")
	assert.Contains(t, wfe.CORS.AllowedOrigins, "https://app.local.trustyca.io:4200")
	ccfg := wfe.IdentityMap.GetCookiesConfig()
	assert.Equal(t, ".local.trustyca.io", ccfg.Domain)
	assert.NotEmpty(t, ccfg.Auth)
	assert.NotEmpty(t, ccfg.CSRF)
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

func TestService_IsLocal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		env, cluster string
		want         bool
	}{
		{env: EnvironmentLocal, cluster: ClusterLocal, want: true},
		// every other environment or cluster fails closed
		{env: EnvironmentDev, cluster: ClusterLocal},
		{env: EnvironmentProd, cluster: ClusterLocal},
		{env: "UNIT_TEST", cluster: ClusterLocal},
		{env: "", cluster: ClusterLocal},
		{env: EnvironmentLocal, cluster: "dev"},
		{env: EnvironmentLocal, cluster: ""},
		{env: "LOCAL", cluster: ClusterLocal},
	}
	for _, tc := range tests {
		got := Service{Environment: tc.env, ClusterName: tc.cluster}.IsLocal()
		assert.Equal(t, tc.want, got, "env=%q cluster=%q", tc.env, tc.cluster)
	}
}

func TestLoadCitestOverride(t *testing.T) {
	// a host name without an entry in the hostmap, so the unit test
	// override of an earlier test does not apply
	t.Setenv("TRUSTYCA_HOSTNAME", "citest")
	// the compose file of the stack sets it
	const sqlConn = "postgres://trustyca@sql:55432?sslmode=disable&dbname=trustycadb"
	t.Setenv("TRUSTYCA_SQL_CONN", sqlConn)

	cfgFile, err := configloader.GetAbsFilename("etc/dev/"+ConfigFileName, projFolder)
	require.NoError(t, err)
	overrideFile, err := configloader.GetAbsFilename("etc/dev/trustyca-config.citest.yaml", projFolder)
	require.NoError(t, err)

	var c Configuration
	require.NoError(t, LoadWithOverride(cfgFile, overrideFile, &c, nil))

	// the integration test stack offers the local identity provider
	assert.True(t, c.Service.IsLocal())
	assert.Empty(t, c.Tasks)
	assert.True(t, c.Metrics.GetDisabled())
	assert.Equal(t, "https://api.local.trustyca.io:8880/v1/auth/authorize", c.Auth.AuthURL)
	assert.Equal(t, sqlConn, c.SQL.DataSource)

	require.NotNil(t, c.Cache.Redis)
	assert.Equal(t, "redis://redis.local.trustyca.io:6379", c.Cache.Redis.Server)
	assert.Equal(t, "redis", c.Cache.Redis.Password)
	require.NotNil(t, c.Cache.Redis.ClientTLS)
	assert.True(t, strings.HasSuffix(c.Cache.Redis.ClientTLS.TrustedCAFile, "/.trustyca/certs/trustyca_root.pem"))

	assert.FileExists(t, c.CryptoProv.Default)
	assert.True(t, strings.HasSuffix(c.CryptoProv.Default, "/kms/aws-dev-kms.citest.yaml"))

	// the rest of the wfe is the dev configuration: the cookie session of
	// the console is tested with its cookies and CORS
	wfe := c.HTTPServers[WFEServerName]
	require.NotNil(t, wfe)
	assert.Equal(t, 15*time.Second, wfe.Timeout.Request)
	assert.True(t, strings.HasSuffix(wfe.ServerTLS.CertFile, "/.trustyca/certs/trustyca_server.pem"))
	assert.Contains(t, wfe.CORS.AllowedOrigins, "https://app.local.trustyca.io:4200")
	ccfg := wfe.IdentityMap.GetCookiesConfig()
	assert.True(t, strings.HasSuffix("api.local.trustyca.io", ccfg.Domain), "the API host is under the cookie domain %s", ccfg.Domain)
	assert.NotEmpty(t, ccfg.Auth)
	assert.NotEmpty(t, ccfg.CSRF)

	// the operator of the tests replaces the operators of the dev
	// configuration on both listeners, and the rest of the DPoP map is kept
	backend := c.HTTPServers[BackendServerName]
	require.NotNil(t, backend)
	operators := map[string][]string{"trustyca-admin": {"operator@trustyca.io"}}
	assert.Equal(t, operators, wfe.IdentityMap.DPoP.Roles)
	assert.Equal(t, operators, backend.IdentityMap.DPoP.Roles)
	assert.True(t, backend.IdentityMap.DPoP.Enabled)
	assert.Equal(t, wfe.IdentityMap.DPoP, backend.IdentityMap.DPoP)
	assert.Equal(t, 15*time.Second, backend.Timeout.Request)
}
