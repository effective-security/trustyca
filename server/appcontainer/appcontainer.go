package appcontainer

import (
	"context"
	"io"
	"os"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/pkg/cache"
	"github.com/effective-security/porto/pkg/discovery"
	"github.com/effective-security/porto/pkg/revocation"
	"github.com/effective-security/porto/pkg/tasks"
	"github.com/effective-security/trustyca/api/client"
	"github.com/effective-security/trustyca/internal/authctx"
	"github.com/effective-security/trustyca/internal/ca"
	"github.com/effective-security/trustyca/internal/config"
	"github.com/effective-security/trustyca/internal/db"
	"github.com/effective-security/xdb/pkg/flake"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/authority"
	"github.com/effective-security/xpki/crypto11"
	"github.com/effective-security/xpki/cryptoprov"
	"github.com/effective-security/xpki/dataprotection"
	"github.com/effective-security/xpki/jwt"
	"github.com/effective-security/xpki/jwt/accesstoken"
	"github.com/effective-security/xpki/jwt/oauth2client"
	"go.uber.org/dig"

	// register providers
	_ "github.com/effective-security/xpki/cryptoprov/awskmscrypto"
	_ "github.com/effective-security/xpki/cryptoprov/gcpkmscrypto"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/trustyca/internal", "appcontainer")

// ContainerFactoryFn defines an app container factory interface
type ContainerFactoryFn func() (*dig.Container, error)

// ProvideConfigurationFn defines Configuration provider
type ProvideConfigurationFn func() (*config.Configuration, error)

// ProvideDiscoveryFn defines Discovery provider
type ProvideDiscoveryFn func() (discovery.Discovery, error)

// ProvideSchedulerFn defines Scheduler provider
type ProvideSchedulerFn func() (tasks.Scheduler, error)

// ProvideJwtFn defines JWT provider
type ProvideJwtFn func(cfg *config.Configuration, dp dataprotection.Provider, cache cache.Provider) (jwt.Parser, jwt.Signer, error)

// ProvideDbFn defines DB provider
type ProvideDbFn func(cfg *config.Configuration) (db.Provider, db.OrgsDb, db.OrgsReadonlyDb, db.CaDb, db.CaReadonlyDb, error)

// ProvideClientFactoryFn defines client.Facroty provider
type ProvideClientFactoryFn func(cfg *config.Configuration) (client.Factory, error)

// ProvideDataprotectionFn defines data protection provider
type ProvideDataprotectionFn func() (dataprotection.Provider, error)

// ProvideAuthorizerFn defines role checker provider
type ProvideAuthorizerFn func(trustycaDb db.OrgsDb) authctx.Authorizer

// ProvideOAuth2ClientsFn defines OAuth2 clients provider
type ProvideOAuth2ClientsFn func(cfg *config.Configuration) (*oauth2client.Provider, error)

// ProvideCryptoFn defines Crypto provider
type ProvideCryptoFn func(cfg *config.Configuration) (*cryptoprov.Crypto, error)

// ProvideCAFn defines the provider of the CA issuer registry
type ProvideCAFn func(cfg *config.Configuration, crypto *cryptoprov.Crypto, dp dataprotection.Provider, caDb db.CaDb) (*ca.Registry, error)

// CloseRegistrator provides interface to release resources on close
type CloseRegistrator interface {
	OnClose(closer io.Closer)
}

// ContainerFactory is default implementation
type ContainerFactory struct {
	closer CloseRegistrator

	configProvider        ProvideConfigurationFn
	discoveryProvider     ProvideDiscoveryFn
	schedulerProvider     ProvideSchedulerFn
	dbProvider            ProvideDbFn
	jwtProvider           ProvideJwtFn
	clientFactoryProvider ProvideClientFactoryFn
	dpProvider            ProvideDataprotectionFn
	oauthProviderProvider ProvideOAuth2ClientsFn
	cryptoProvider        ProvideCryptoFn
	caProvider            ProvideCAFn
	cacheProvider         ProvideCacheFn
	authorizerProvider    ProvideAuthorizerFn

	// awsSessionProvider    ProvideAwsFactoryFn
}

// NewContainerFactory returns an instance of ContainerFactory
func NewContainerFactory(closer CloseRegistrator) *ContainerFactory {
	f := &ContainerFactory{
		closer: closer,
	}

	defaultSchedulerProv := func() (tasks.Scheduler, error) {
		return tasks.NewScheduler(), nil
	}

	// configure with default providers
	return f.
		WithDiscoveryProvider(provideDiscovery).
		//WithAwsSessionProvider(provideAwsSession).
		WithSchedulerProvider(defaultSchedulerProv).
		WithJwtProvider(provideJwt).
		WithDbProvider(provideDb).
		WithClientFactoryProvider(provideClientFactory).
		WithDataprotectionProvider(provideDp).
		WithCacheProvider(provideCache).
		WithAuthorizerProvider(provideAuthorizer).
		WithOAuth2ClientsProvider(provideOAuth2Clients).
		WithCryptoProvider(provideCrypto).
		WithCAProvider(provideCA)
}

// WithConfigurationProvider allows to specify configuration
func (f *ContainerFactory) WithConfigurationProvider(p ProvideConfigurationFn) *ContainerFactory {
	f.configProvider = p
	return f
}

// WithCryptoProvider allows to specify custom Crypto loader
func (f *ContainerFactory) WithCryptoProvider(p ProvideCryptoFn) *ContainerFactory {
	f.cryptoProvider = p
	return f
}

// WithCAProvider allows to specify a custom provider of the CA issuer
// registry
func (f *ContainerFactory) WithCAProvider(p ProvideCAFn) *ContainerFactory {
	f.caProvider = p
	return f
}

// WithCacheProvider allows to specify Cache provider
func (f *ContainerFactory) WithCacheProvider(p ProvideCacheFn) *ContainerFactory {
	f.cacheProvider = p
	return f
}

// WithDiscoveryProvider allows to specify Discovery
func (f *ContainerFactory) WithDiscoveryProvider(p ProvideDiscoveryFn) *ContainerFactory {
	f.discoveryProvider = p
	return f
}

// WithDataprotectionProvider allows to specify Data protection provider
func (f *ContainerFactory) WithDataprotectionProvider(p ProvideDataprotectionFn) *ContainerFactory {
	f.dpProvider = p
	return f
}

// WithClientFactoryProvider allows to specify custom client.Factory provider
func (f *ContainerFactory) WithClientFactoryProvider(p ProvideClientFactoryFn) *ContainerFactory {
	f.clientFactoryProvider = p
	return f
}

// WithJwtProvider allows to specify custom JWT provider
func (f *ContainerFactory) WithJwtProvider(p ProvideJwtFn) *ContainerFactory {
	f.jwtProvider = p
	return f
}

// WithDbProvider allows to specify custom DB provider
func (f *ContainerFactory) WithDbProvider(p ProvideDbFn) *ContainerFactory {
	f.dbProvider = p
	return f
}

// WithSchedulerProvider allows to specify custom Scheduler
func (f *ContainerFactory) WithSchedulerProvider(p ProvideSchedulerFn) *ContainerFactory {
	f.schedulerProvider = p
	return f
}

// WithAuthorizerProvider allows to specify custom RoleChecker provider
func (f *ContainerFactory) WithAuthorizerProvider(p ProvideAuthorizerFn) *ContainerFactory {
	f.authorizerProvider = p
	return f
}

// WithOAuth2ClientsProvider allows to specify custom OAuth2 clients provider
func (f *ContainerFactory) WithOAuth2ClientsProvider(p ProvideOAuth2ClientsFn) *ContainerFactory {
	f.oauthProviderProvider = p
	return f
}

// ProvideCacheFn defines Cache provider
type ProvideCacheFn func(cfg *config.Configuration, closer CloseRegistrator) (cache.Provider, error)

// CreateContainerWithDependencies returns an instance of Container
func (f *ContainerFactory) CreateContainerWithDependencies() (*dig.Container, error) {
	container := dig.New()

	constructors := []any{
		f.configProvider,
		func() CloseRegistrator {
			return f.closer
		},
		f.discoveryProvider,
		f.schedulerProvider,
		f.jwtProvider,
		f.dbProvider,
		f.clientFactoryProvider,
		f.dpProvider,
		f.cacheProvider,
		f.authorizerProvider,
		f.oauthProviderProvider,
		f.cryptoProvider,
		f.caProvider,
	}

	for idx, c := range constructors {
		err := container.Provide(c)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to provide constructor %d: %T", idx, c)
		}
	}

	return container, nil
}

func provideDiscovery() (discovery.Discovery, error) {
	return discovery.New(), nil
}

// provideJwt returns the token parser and signer. A revoked token (Auth.RevokeToken,
// the sign-out of a bearer or cookie session) is refused at once by the
// process that revoked it, and by the others once they reload the revoked
// IDs from the cache, within the snapshot TTL of porto/pkg/revocation.
func provideJwt(cfg *config.Configuration, dp dataprotection.Provider, cache cache.Provider) (jwt.Parser, jwt.Signer, error) {
	var provider jwt.Provider
	var err error
	if cfg.Auth.JWT != "" {
		provider, err = jwt.LoadProvider(cfg.Auth.JWT, nil)
		if err != nil {
			return nil, nil, err
		}
	}
	// we encrypt Admin access token,
	// the accesstoken provider handles both, encrypted PAT and plain JWT
	at := accesstoken.New(dp, provider)
	at.SetRevocation(revocation.New(cache))
	return at, at, nil
}

func provideDb(cfg *config.Configuration) (db.Provider, db.OrgsDb, db.OrgsReadonlyDb, db.CaDb, db.CaReadonlyDb, error) {
	d, err := db.New(
		cfg.SQL.DataSource,
		cfg.SQL.MigrationsDir,
		cfg.SQL.ForceVersion,
		cfg.SQL.MigrateVersion,
		flake.DefaultIDGenerator)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	return d, d, d, d, d, nil
}

func provideClientFactory(cfg *config.Configuration) (client.Factory, error) {
	var ops []client.Option
	// if cfg.Client.EnableCNA {
	// 	ci := awsprov.NewCallerIdentity(awsFactory, 5*time.Minute, nil)
	// 	ops = append(ops, client.WithCallerIdentity(ci))
	// }
	f, err := client.NewFactory(cfg.Clients, ops...)
	if err != nil {
		return nil, errors.WithMessage(err, "invalid clients configuration")
	}
	return f, nil
}

func provideOAuth2Clients(cfg *config.Configuration) (*oauth2client.Provider, error) {
	ocfg, err := oauth2client.LoadConfig(cfg.Auth.OAuth2Clients)
	if err != nil {
		return nil, err
	}
	return oauth2client.NewProvider(ocfg)
}

// provideAuthorizer gives the whole app one role checker, so a service that
// invalidates its cache clears the cache the authz interceptor reads.
func provideAuthorizer(trustycaDb db.OrgsDb) authctx.Authorizer {
	return authctx.NewAuthorizer(trustycaDb)
}

func provideDp() (dataprotection.Provider, error) {
	seed := os.Getenv("TRUSTYCA_DP_SEED")
	if seed == "" {
		logger.KV(xlog.ERROR, "err", "TRUSTYCA_DP_SEED not defined")
		return nil, errors.Errorf("TRUSTYCA_DP_SEED not defined")
	}
	p, err := dataprotection.NewSymmetric([]byte(seed))
	if err != nil {
		return nil, err
	}
	return p, nil
}

func provideCache(cfg *config.Configuration, closer CloseRegistrator) (p cache.Provider, err error) {
	// the root should be the same for all services
	rootKey := "/trustyca"
	switch cfg.Cache.Provider {
	case "redis":
		if cfg.Cache.Redis == nil ||
			cfg.Cache.Redis.Server == "" {
			return nil, errors.New("invalid redis config")
		}
		p, err = cache.NewRedisProvider(*cfg.Cache.Redis, rootKey)
		if err != nil {
			return
		}
	case "memory", "default", "":
		p = cache.NewMemoryProvider(rootKey)
	}
	if p == nil {
		return nil, errors.Errorf("unsupported cache provider: %s", cfg.Cache.Provider)
	}
	if closer != nil {
		closer.OnClose(p)
	}
	return
}

func provideCrypto(cfg *config.Configuration) (*cryptoprov.Crypto, error) {
	logger.KV(xlog.TRACE,
		"default", cfg.CryptoProv.Default,
		"providers", cfg.CryptoProv.Providers)

	for _, m := range cfg.CryptoProv.PKCS11Manufacturers {
		_ = cryptoprov.Register(m, crypto11.LoadProvider)
	}

	if strings.Contains(cfg.CryptoProv.Default, "aws-dev-kms") && os.Getenv("AWS_ACCESS_KEY_ID") == "" {
		os.Setenv("AWS_ACCESS_KEY_ID", "notusedbyemulator")
		os.Setenv("AWS_SECRET_ACCESS_KEY", "notusedbyemulator")
		os.Setenv("AWS_DEFAULT_REGION", "us-west-2")
	}

	crypto, err := cryptoprov.Load(cfg.CryptoProv.Default, cfg.CryptoProv.Providers)
	if err != nil {
		//logger.KV(xlog.ERROR, "default", cfg.CryptoProv.Default, "providers", cfg.CryptoProv.Providers, "err", err)
		return nil, err
	}
	return crypto, nil
}

// provideCA gives the CA service its issuer registry over the CA tables,
// the crypto providers and the data protection provider, and mirrors the
// platform issuers and profiles of `ca.bootstrap_config` into the platform
// rows first. The bootstrap loads every enabled platform issuer: one whose
// key does not load or whose delegated OCSP profile does not bind fails the
// start.
func provideCA(cfg *config.Configuration, crypto *cryptoprov.Crypto, dp dataprotection.Provider, caDb db.CaDb) (*ca.Registry, error) {
	if cfg.CA.AllowSoftwareKeys && cfg.Service.Environment == config.EnvironmentProd {
		return nil, errors.New("ca.allow_software_keys is not allowed in the prod environment: issuer keys must live in a crypto provider")
	}
	keys := ca.NewKeys(crypto, dp)
	if !cfg.CA.AllowSoftwareKeys {
		keys.DisableSoftwareKeys()
	}
	registry := ca.NewRegistry(caDb, keys, ca.Options{
		TTL:  cfg.CA.IssuerCacheTTL,
		Size: cfg.CA.IssuerCacheSize,
	})
	if path := cfg.CA.BootstrapConfig; path != "" {
		acfg, err := authority.LoadConfig(path)
		if err != nil {
			return nil, errors.WithMessagef(err, "failed to load CA bootstrap config: %s", path)
		}
		res, err := registry.Bootstrap(context.Background(), caDb, acfg)
		if err != nil {
			return nil, errors.WithMessage(err, "failed to bootstrap CA")
		}
		logger.KV(xlog.INFO,
			"status", "ca_bootstrapped",
			"issuers", res.Issuers,
			"updated", res.Updated,
			"archived", res.Archived,
			"roots", res.Roots,
			"profiles", res.Profiles)
	}
	return registry, nil
}
