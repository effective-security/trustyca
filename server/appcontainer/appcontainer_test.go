package appcontainer

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"os"
	"path"
	"path/filepath"
	"sync"
	"testing"

	"github.com/effective-security/porto/pkg/cache"
	"github.com/effective-security/porto/pkg/tasks"
	"github.com/effective-security/trustyca/api/client"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/authctx"
	"github.com/effective-security/trustyca/internal/ca"
	"github.com/effective-security/trustyca/internal/config"
	"github.com/effective-security/trustyca/internal/db"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/tests/testutils"
	"github.com/effective-security/x/guid"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xpki/authority"
	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/jwt"
	"github.com/effective-security/xpki/jwt/oauth2client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/dig"
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

// devContainer builds the container of the dev configuration over the
// local stack. The seed the platform issuers in the dev DB are wrapped
// under must be the one of every process that uses that DB.
func devContainer(t *testing.T) *dig.Container {
	t.Helper()
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
	return container
}

func TestAppContainer(t *testing.T) {
	container := devContainer(t)
	err := container.Invoke(func(
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

// TestBootstrap_ConcurrentStart bootstraps one new platform issuer from
// several goroutines at once over the dev DB, as the service instances and
// the test packages do against a fresh DB: every bootstrap succeeds, and
// the issuer is registered once
func TestBootstrap_ConcurrentStart(t *testing.T) {
	container := devContainer(t)
	var registry *ca.Registry
	var caDb db.CaDb
	require.NoError(t, container.Invoke(func(r *ca.Registry, c db.CaDb) {
		registry, caDb = r, c
	}))
	ctx := context.Background()

	label := "race_" + guid.MustCreate()[:12]
	root := testutils.NewTestCA(t, "Race Root "+label, nil)
	dir := t.TempDir()
	der, err := x509.MarshalECPrivateKey(root.Key)
	require.NoError(t, err)
	certPath := filepath.Join(dir, "root.pem")
	keyPath := filepath.Join(dir, "root.key")
	require.NoError(t, os.WriteFile(certPath, []byte(testutils.CertPEM(root.Cert)), 0600))
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0600))
	cfg := &authority.Config{
		Authority: &authority.CAConfig{
			Issuers: []authority.IssuerConfig{{
				Label:    label,
				CertFile: certPath,
				KeyFile:  keyPath,
			}},
		},
	}
	skid := certutil.GetSubjectKeyID(root.Cert)
	t.Cleanup(func() {
		if row, err := caDb.FindIssuer(ctx, 0, 0, label); err == nil {
			_, _ = caDb.DeleteIssuer(ctx, 0, row.ID.UInt64())
		}
		if roots, err := caDb.ListRoots(ctx, &query.ListRootsRequest{Platform: true, Limit: 500}); err == nil {
			for _, r := range roots.Rows {
				if r.Skid == skid {
					_, _ = caDb.DeleteRoot(ctx, 0, r.ID.UInt64())
				}
			}
		}
	})

	const starters = 4
	var start sync.WaitGroup
	start.Add(1)
	results := make([]*ca.BootstrapResult, starters)
	errs := make([]error, starters)
	var done sync.WaitGroup
	for i := range starters {
		done.Add(1)
		go func() {
			defer done.Done()
			start.Wait()
			results[i], errs[i] = registry.Bootstrap(ctx, caDb, cfg)
		}()
	}
	start.Done()
	done.Wait()

	registered := 0
	for i := range starters {
		require.NoError(t, errs[i], "bootstrap %d", i)
		registered += results[i].Issuers
	}
	assert.Equal(t, 1, registered, "one bootstrap registered the issuer, the others continued with its row")
	list, err := caDb.ListIssuers(ctx, &query.ListIssuersRequest{Platform: true, Label: label, Limit: 10})
	require.NoError(t, err)
	require.Len(t, list.Rows, 1)
	assert.Equal(t, skid, list.Rows[0].Skid)
	assert.Equal(t, pb.IssuerStatus_Active, list.Rows[0].Status)

	// the lost race itself, whatever the goroutines did: a lookup that
	// misses the row makes the insert hit the driver's unique violation,
	// and the bootstrap continues with the row
	missed := &missedLookup{CaDb: caDb, label: label, misses: 1}
	res, err := registry.Bootstrap(ctx, missed, cfg)
	require.NoError(t, err)
	assert.Equal(t, &ca.BootstrapResult{Roots: 1}, res, "nothing registered or updated: the row is the issuer, whose anchor is registered again")
	assert.Equal(t, 1, missed.inserts, "the insert was attempted")
	assert.Equal(t, 0, missed.misses, "the miss was consumed")
}

// missedLookup is a CaDb whose first lookups of the label by scope miss,
// as the lookup of an instance that loses the insert race does
type missedLookup struct {
	db.CaDb
	label   string
	misses  int
	inserts int
}

func (m *missedLookup) FindIssuer(ctx context.Context, orgID, projectID uint64, label string) (*model.Issuer, error) {
	if label == m.label && m.misses > 0 {
		m.misses--
		return nil, xdb.CheckNotFoundError(sql.ErrNoRows, "issuer", label)
	}
	return m.CaDb.FindIssuer(ctx, orgID, projectID, label)
}

func (m *missedLookup) RegisterIssuer(ctx context.Context, row *model.Issuer, anchor *model.RootCertificate) (*model.Issuer, error) {
	m.inserts++
	return m.CaDb.RegisterIssuer(ctx, row, anchor)
}

// TestProvideCA_SoftwareKeys covers the production guard of the issuer
// keys: a prod environment refuses to start with software keys allowed
func TestProvideCA_SoftwareKeys(t *testing.T) {
	cfg := &config.Configuration{
		Service: config.Service{Environment: config.EnvironmentProd},
		CA:      config.CA{AllowSoftwareKeys: true},
	}
	_, err := provideCA(cfg, nil, nil, nil)
	require.EqualError(t, err, "ca.allow_software_keys is not allowed in the prod environment: issuer keys must live in a crypto provider")

	// without a bootstrap, the registry is built with the keys disabled
	cfg.CA.AllowSoftwareKeys = false
	registry, err := provideCA(cfg, nil, nil, nil)
	require.NoError(t, err)
	_, _, err = registry.Keys().ImportKey(context.Background(), "", []byte("key"), "label", nil)
	assert.ErrorIs(t, err, ca.ErrSoftwareKeysDisabled)

	// a development environment allows them
	cfg.Service.Environment = "dev"
	cfg.CA.AllowSoftwareKeys = true
	registry, err = provideCA(cfg, nil, nil, nil)
	require.NoError(t, err)
	_, _, err = registry.Keys().ImportKey(context.Background(), "", []byte("key"), "label", nil)
	assert.NotErrorIs(t, err, ca.ErrSoftwareKeysDisabled, "refused for another reason: %v", err)
}
