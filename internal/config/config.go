package config

import (
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
