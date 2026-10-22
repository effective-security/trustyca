package config

import (
	"time"

	"github.com/effective-security/porto/gserver"
	appinit "github.com/effective-security/porto/pkg/appinit/config"
	"github.com/effective-security/porto/pkg/cache"
	"github.com/effective-security/trustyca/api/client"
	"github.com/effective-security/xlog"
)

const (
	// WFEServerName specifies server name for Web Front End
	WFEServerName     = "wfe"
	BackendServerName = "backend"
	RouterServerName  = "router"
	// AIAServerName is the plain HTTP listener of the Authority Information
	// Access service: the AIA, CRL and OCSP routes of the issued certificates
	AIAServerName = "aia"

	// EnvironmentProd is the service.environment of a production instance: it
	// refuses the settings of development, such as software issuer keys
	EnvironmentProd = "prod"
	// EnvironmentDev is the service.environment of a development instance it
	// refuses the settings of development, such as software issuer keys
	EnvironmentDev = "dev"
	// EnvironmentLocal is the service.environment of a local instance: it
	// allows software issuer keys
	EnvironmentLocal = "local"
)

// Configuration contains the user configurable data for the service
type Configuration struct {
	// Service specifies the service configuration
	Service Service `json:"service" yaml:"service"`

	// Metrics specifies the metrics pipeline configuration
	Metrics appinit.Metrics `json:"metrics" yaml:"metrics"`

	// LogLevels specifies the log levels per package
	LogLevels []xlog.RepoLogLevel `json:"log_levels" yaml:"log_levels"`

	// Auth specifies the authentication configuration
	Auth Auth `json:"auth" yaml:"auth"`

	// SQL specifies the configuration for SQL provider
	SQL SQL `json:"sql" yaml:"sql"`

	// // AWS specifies the AWS configuration
	// AWS AWS `json:"aws" yaml:"aws"`

	// Cache specifies configuration of the cache.
	Cache Cache `json:"cache" yaml:"cache"`

	// HTTPServers specifies a list of servers that expose HTTP or gRPC services
	HTTPServers map[string]*gserver.Config `json:"servers" yaml:"servers"`

	// Client specifies configurations for the client to connect to the cluster
	Client client.Config `json:"client" yaml:"client"`

	// Tasks specifies array of tasks
	Tasks []Task `json:"tasks" yaml:"tasks"`

	// Orgs specifies the Orgs configuration
	Orgs Orgs `json:"orgs" yaml:"orgs"`

	// CryptoProv specifies the configuration for crypto providers
	CryptoProv CryptoProv `json:"crypto_provider" yaml:"crypto_provider"`

	// CA specifies the Certification Authority configuration
	CA CA `json:"ca" yaml:"ca"`

	// AIA specifies the Authority Information Access service configuration
	AIA AIA `json:"aia" yaml:"aia"`
}

// Service specifies the basic service info
type Service struct {
	// Name specifies the service name to be used in logs, metrics, etc
	Name string `json:"name,omitempty" yaml:"name,omitempty"`

	// Region specifies the Region / Datacenter where the instance is running
	Region string `json:"region,omitempty" yaml:"region,omitempty"`

	// Environment specifies the environment where the instance is running: prod|stage|dev
	Environment string `json:"environment,omitempty" yaml:"environment,omitempty"`

	// ClusterName specifies the cluster name
	ClusterName string `json:"cluster,omitempty" yaml:"cluster,omitempty"`
}

// Auth specifies the authentication configuration
type Auth struct {
	// AuthURL specifies the login URL
	AuthURL string `json:"auth_url,omitempty" yaml:"auth_url,omitempty"`

	// JWT specifies configuration file for the JWT provider
	JWT string `json:"jwt_provider" yaml:"jwt_provider"`

	// OAuth2Clients specifies configuration file for the OAuth2 Clients provider
	OAuth2Clients string `json:"oauth2_clients" yaml:"oauth2_clients"`

	// AllowedDomains specifies the list of email domains
	// allowed to login without invitation.
	AllowedDomains []string `json:"allowed_domains" yaml:"allowed_domains"`

	// AllowedRedirectDomains specifies the list of allowed redirect URL domains
	AllowedRedirectDomains []string `json:"allowed_redirect_domains" yaml:"allowed_redirect_domains"`

	// RecaptchaSiteKey specifies the reCAPTCHA v3 site key rendered on the
	// login page. When empty, the page does not load reCAPTCHA.
	RecaptchaSiteKey string `json:"recaptcha_site_key,omitempty" yaml:"recaptcha_site_key,omitempty"`
}

// Cache specifies configuration of the cache.
type Cache struct {
	// Provider specifies the default cache provider: redis|memory
	Provider string             `json:"provider" yaml:"provider"`
	Redis    *cache.RedisConfig `json:"redis" yaml:"redis"`
	// Disable specifies the list of cache types to disable:
	// search_org: for Org level search requests on Facets and aggregations
	// stats: for daily stats, sla, summaries and funnels
	Disable map[string]bool `json:"disable" yaml:"disable"`
	// StatsFolder specifies to use files for caching stats instead of Redis
	StatsFolder string `json:"stats_folder" yaml:"stats_folder"`
}

// Task specifies configuration of a single task.
type Task struct {
	// Name specifies the name of the task.
	Name string `json:"name" yaml:"name"`

	// Schedule specifies the schedule of this task.
	Schedule string `json:"schedule" yaml:"schedule"`

	// Args specifies parameters for the task.
	Args []string `json:"args" yaml:"args"`
}

// Orgs specifies the Orgs configuration
type Orgs struct {
	// DefaultOrgName specifies the default org name to be created for new users.
	// If empty, no default org will be created.
	DefaultOrgName string `json:"default_org_name" yaml:"default_org_name"`
	// DefaultProjectName specifies the default project name to be created for new users.
	// If empty, no default project will be created.
	DefaultProjectName string `json:"default_project_name" yaml:"default_project_name"`
}

// CryptoProv specifies the configuration for crypto providers
type CryptoProv struct {
	// Default specifies the location of the configuration file for default provider
	Default string `json:"default,omitempty" yaml:"default,omitempty"`

	// Providers specifies the list of locations of the configuration files
	Providers []string `json:"providers,omitempty" yaml:"providers,omitempty"`

	// PKCS11Manufacturers specifies the list of supported manufactures of PKCS11 tokens
	PKCS11Manufacturers []string `json:"pkcs11_manufacturers,omitempty" yaml:"pkcs11_manufacturers,omitempty"`
}

// CA specifies the Certification Authority configuration
type CA struct {
	// BootstrapConfig specifies the authority configuration file with the
	// platform issuers and profiles. They are mirrored into the platform
	// rows (org_id IS NULL) at startup; empty disables the bootstrap.
	BootstrapConfig string `json:"bootstrap_config" yaml:"bootstrap_config"`

	// IssuerCacheTTL bounds the staleness of the issuers and profiles the CA
	// keeps in memory: a change made by another instance is visible after
	// the TTL. The default is 5 minutes.
	IssuerCacheTTL time.Duration `json:"issuer_cache_ttl" yaml:"issuer_cache_ttl"`

	// IssuerCacheSize is the number of issuers kept in memory; the least
	// recently used issuer is evicted first. The default is 1000.
	IssuerCacheSize int `json:"issuer_cache_size" yaml:"issuer_cache_size"`

	// Retention specifies how long expired certificates are kept; the
	// cert_status task applies it.
	Retention Retention `json:"retention" yaml:"retention"`

	// AllowSoftwareKeys allows issuer keys that no crypto provider holds:
	// the keys the inmem provider generates, the PEM keys of ImportIssuer
	// and the key files of the bootstrap config, which are stored wrapped
	// by the data protection provider (key_protected). Off by default, so
	// that every issuer key lives in a crypto provider (KMS, HSM); on in
	// development. A prod environment (service.environment) refuses to
	// start with it on.
	AllowSoftwareKeys bool `json:"allow_software_keys" yaml:"allow_software_keys"`
}

// AIA specifies the Authority Information Access service configuration:
// the public, read-only service over plain HTTP that serves the issuer
// certificates, CRLs and OCSP responses the issued certificates point at.
// It holds no keys: OCSP requests are forwarded to the CA over the backend
// gRPC client (`client.server_url.backend`).
type AIA struct {
	// ClientTLS specifies the TLS certificate the AIA presents to the CA
	// backend, mapped to the `trustyca-aia` role by the backend listener
	// (`spiffe://trustyca/aia`). Empty uses the `client.client_tls`
	// certificate.
	ClientTLS gserver.TLSInfo `json:"client_tls,omitempty" yaml:"client_tls,omitempty"`

	// OcspCacheSize is the number of OCSP responses kept in memory, keyed by
	// the hash of the request and served until the NextUpdate of the
	// response; the least recently used response is evicted first. The
	// default is 10000.
	OcspCacheSize int `json:"ocsp_cache_size" yaml:"ocsp_cache_size"`
}

// Retention specifies the retention of expired certificates
type Retention struct {
	// ExpiredAfter is how long after the end of its validity a certificate
	// and its revocation are deleted. Zero keeps expired certificates
	// forever.
	ExpiredAfter time.Duration `json:"expired_after" yaml:"expired_after"`
}
