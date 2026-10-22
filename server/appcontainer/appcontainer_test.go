package appcontainer

import (
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/effective-security/porto/pkg/cache"
	"github.com/effective-security/porto/pkg/tasks"
	"github.com/effective-security/trustyca/api/client"
	"github.com/effective-security/trustyca/internal/authctx"
	"github.com/effective-security/trustyca/internal/ca"
	"github.com/effective-security/trustyca/internal/config"
	"github.com/effective-security/trustyca/internal/db"
	"github.com/effective-security/trustyca/tests/testutils"
	"github.com/effective-security/x/guid"
	"github.com/effective-security/xpki/jwt"
	"github.com/effective-security/xpki/jwt/oauth2client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const projFolder = "../../"

func TestNewContainerFactory(t *testing.T) {
	output := path.Join(os.TempDir(), "tests", "trustyca", guid.MustCreate())
	_ = os.MkdirAll(output, 0777)
	defer os.Remove(output)

	tcases := []struct {
		name string
		err  string
		cfg  *config.Configuration
	}{
		{
			name: "default",
			cfg:  &config.Configuration{},
		},
	}

	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			container, err := NewContainerFactory(nil).
				WithConfigurationProvider(func() (*config.Configuration, error) {
					return tc.cfg, nil
				}).
				CreateContainerWithDependencies()
			require.NoError(t, err)

			err = container.Invoke(func(cfg *config.Configuration,
				scheduler tasks.Scheduler,
			) {
			})
			if tc.err == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Equal(t, tc.err, err.Error())
			}
		})
	}
}

func TestAppContainer(t *testing.T) {
	// the seed the platform issuer in the dev DB is wrapped under must be
	// the one of every process that uses that DB
	testutils.SetDataProtectionSeed(t)
	t.Setenv("TRUSTYCA_GITHUB_CLIENT_ID", "testclientid")
	t.Setenv("TRUSTYCA_GITHUB_CLIENT_SECRET", "testclientsecret")
	cfgPath, err := filepath.Abs(projFolder + "etc/dev/" + config.ConfigFileName)
	require.NoError(t, err)

	f := NewContainerFactory(nil).
		WithConfigurationProvider(func() (*config.Configuration, error) {

			f, err := config.DefaultFactory()
			require.NoError(t, err)

			cfg := new(config.Configuration)
			_, err = f.LoadForHostName(cfgPath, "", cfg)
			require.NoError(t, err)

			return cfg, nil
		})

	container, err := f.CreateContainerWithDependencies()
	require.NoError(t, err)
	err = container.Invoke(func(
		_ *config.Configuration,
		_ tasks.Scheduler,
		_ db.Provider,
		_ db.OrgsDb,
		_ cache.Provider,
		_ jwt.Parser,
		_ client.Factory,
		_ authctx.Authorizer,
		_ *oauth2client.Provider,
		registry *ca.Registry,
	) {
		// the platform issuers of ca.bootstrap_config are mirrored into
		// the DB when the registry is provided
		require.NotNil(t, registry)
	})
	require.NoError(t, err)
}
