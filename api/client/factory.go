package client

import (
	"crypto/tls"
	"io"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/gserver"
	"github.com/effective-security/porto/gserver/credentials"
	"github.com/effective-security/porto/pkg/rpcclient"
	"github.com/effective-security/porto/pkg/tlsconfig"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/api/pb/proxypb"
	"github.com/effective-security/trustyca/privpb"
	privproxypb "github.com/effective-security/trustyca/privpb/proxypb"
	"github.com/effective-security/x/fileutil/resolve"
)

//go:generate mockgen -source=factory.go -destination=../../mocks/mockclient/client_mock.gen.go -package mockclient

const (
	// UserAgentWfe is the user agent of the clients of the service
	UserAgentWfe = "trustyca"
	// ClientNameDefault is the client of a process that has a single
	// identity, such as a tool
	ClientNameDefault = "default"
	// ClientNameAIA is the client the AIA service forwards OCSP requests to
	// the backend with: the trustyca-aia identity
	ClientNameAIA = "aia"
	// ClientNameCA is the client the CA service of a process without the
	// backend service forwards the calls of its tenants with: the identity
	// of the WFE (trustyca-peer)
	ClientNameCA = "ca"
)

// Config specifies a named service client: the certificate it presents and
// the URLs of the listeners it dials. A process holds one client per
// identity it calls other listeners with (DESIGN.md section 2.2).
type Config struct {
	// Name is the name the services select the client by, unique in the
	// `clients` list
	Name string `json:"name,omitempty" yaml:"name,omitempty"`

	// ClientTLS describes the TLS certificate the client presents and the
	// roots it trusts
	ClientTLS gserver.TLSInfo `json:"client_tls,omitempty" yaml:"client_tls,omitempty"`

	// ServerURL specifies the URL of each listener the client dials, by
	// listener name (wfe, backend)
	ServerURL map[string]string `json:"server_url,omitempty" yaml:"server_url,omitempty"`

	// DialTimeout is the timeout for failing to establish a connection.
	DialTimeout time.Duration `json:"dial_timeout,omitempty" yaml:"dial_timeout,omitempty"`

	// DialKeepAliveTime is the time after which client pings the server to see if
	// transport is alive.
	DialKeepAliveTime time.Duration `json:"dial_keep_alive_time,omitempty" yaml:"dial_keep_alive_time,omitempty"`

	// DialKeepAliveTimeout is the time that the client waits for a response for the
	// keep-alive probe. If the response is not received in this time, the connection is closed.
	DialKeepAliveTimeout time.Duration `json:"dial_keep_alive_timeout,omitempty" yaml:"dial_keep_alive_timeout,omitempty"`

	// EnableCNA enables Cloud Native Auth
	EnableCNA bool `json:"enable_cna,omitempty" yaml:"enable_cna,omitempty"`
}

// Factory creates the gRPC clients of the services: every method dials the
// listener named server with the TLS identity and settings of the named
// client, and returns the closer of the connection
type Factory interface {
	// StatusClient returns Status client
	StatusClient(clientName, server string, ops ...Option) (pb.StatusServer, io.Closer, error)

	// OrgsClient returns Orgs client
	OrgsClient(clientName, server string, ops ...Option) (pb.OrgsServer, io.Closer, error)

	// CAClient returns CA client
	CAClient(clientName, server string, ops ...Option) (pb.CAServer, io.Closer, error)

	// CISClient returns CIS client
	CISClient(clientName, server string, ops ...Option) (pb.CISServer, io.Closer, error)

	// BackendClient returns the client of the signing plane (privpb.Backend)
	BackendClient(clientName, server string, ops ...Option) (privpb.BackendServer, io.Closer, error)
}

// Option configures how we set up the client
type Option struct {
	f func(*options)
}

type options struct {
	tlsCfg         *tls.Config
	callerIdentity credentials.CallerIdentity
	agent          string
}

func (fo *Option) apply(o *options) {
	fo.f(o)
}

func newFuncOption(f func(*options)) Option {
	return Option{
		f: f,
	}
}

// WithTLS option to provide tls.Config
func WithTLS(tlsCfg *tls.Config) Option {
	return newFuncOption(func(o *options) {
		o.tlsCfg = tlsCfg
	})
}

// WithCallerIdentity option to provide CallerIdentity
func WithCallerIdentity(callerIdentity credentials.CallerIdentity) Option {
	return newFuncOption(func(o *options) {
		o.callerIdentity = callerIdentity
	})
}

// WithAgent option to provide client Agent
func WithAgent(agent string) Option {
	return newFuncOption(func(o *options) {
		o.agent = agent
	})
}

type factory struct {
	dops options
	cfgs map[string]*Config
}

// NewFactory returns the Factory of the named clients; a client without a
// name, or two clients with the same name, is an error
func NewFactory(cfgs []Config, ops ...Option) (Factory, error) {
	f := &factory{
		cfgs: make(map[string]*Config, len(cfgs)),
		dops: options{},
	}
	for i, cfg := range cfgs {
		if cfg.Name == "" {
			return nil, errors.Errorf("client %d has no name", i)
		}
		if _, ok := f.cfgs[cfg.Name]; ok {
			return nil, errors.Errorf("duplicate client: %s", cfg.Name)
		}
		f.cfgs[cfg.Name] = &cfg
	}

	for _, op := range ops {
		op.apply(&f.dops)
	}

	return f, nil
}

// NewClient dials the listener named server with the named client
func (f *factory) NewClient(clientName, server string, ops ...Option) (*rpcclient.Client, error) {
	var err error

	dops := f.dops
	for _, op := range ops {
		op.apply(&dops)
	}

	cfg := f.cfgs[clientName]
	if cfg == nil {
		return nil, errors.Errorf("client %s not found", clientName)
	}

	targetHost := cfg.ServerURL[server]
	if targetHost == "" {
		return nil, errors.Errorf("server %s not found in client %s", server, clientName)
	}

	// the TLS configuration of the WithTLS option, else one built from the
	// client TLS files for an https server
	tlscfg := dops.tlsCfg
	if tlscfg == nil && strings.HasPrefix(targetHost, "https://") {
		var tlsCert, tlsKey string
		tlsCA := resolve.ExpandPath(cfg.ClientTLS.TrustedCAFile)
		if !cfg.ClientTLS.Empty() {
			tlsCert = resolve.ExpandPath(cfg.ClientTLS.CertFile)
			tlsKey = resolve.ExpandPath(cfg.ClientTLS.KeyFile)
		}

		tlscfg, err = tlsconfig.NewClientTLSFromFiles(
			tlsCert,
			tlsKey,
			tlsCA)
		if err != nil {
			return nil, errors.WithMessage(err, "unable to build TLS configuration")
		}
	}

	clientCfg := &rpcclient.Config{
		DialTimeout:          cfg.DialTimeout,
		DialKeepAliveTimeout: cfg.DialKeepAliveTimeout,
		DialKeepAliveTime:    cfg.DialKeepAliveTime,
		Endpoint:             targetHost,
		TLS:                  tlscfg,
		CallerIdentity:       dops.callerIdentity,
		UserAgent:            dops.agent,
	}
	client, err := rpcclient.New(clientCfg)
	if err != nil {
		return nil, errors.WithMessagef(err, "unable to create client: %v", targetHost)
	}
	return client, nil
}

// StatusClient returns Status client from connection
func (f *factory) StatusClient(clientName, server string, ops ...Option) (pb.StatusServer, io.Closer, error) {
	c, err := f.NewClient(clientName, server, ops...)
	if err != nil {
		return nil, nil, err
	}
	return proxypb.NewStatusClient(c.Conn(), c.Opts()), c, nil
}

// OrgsClient returns Orgs client from connection
func (f *factory) OrgsClient(clientName, server string, ops ...Option) (pb.OrgsServer, io.Closer, error) {
	c, err := f.NewClient(clientName, server, ops...)
	if err != nil {
		return nil, nil, err
	}
	return proxypb.NewOrgsClient(c.Conn(), c.Opts()), c, nil
}

// CAClient returns CA client from connection
func (f *factory) CAClient(clientName, server string, ops ...Option) (pb.CAServer, io.Closer, error) {
	c, err := f.NewClient(clientName, server, ops...)
	if err != nil {
		return nil, nil, err
	}
	return proxypb.NewCAClient(c.Conn(), c.Opts()), c, nil
}

// CISClient returns CIS client from connection
func (f *factory) CISClient(clientName, server string, ops ...Option) (pb.CISServer, io.Closer, error) {
	c, err := f.NewClient(clientName, server, ops...)
	if err != nil {
		return nil, nil, err
	}
	return proxypb.NewCISClient(c.Conn(), c.Opts()), c, nil
}

// BackendClient returns Backend client from connection
func (f *factory) BackendClient(clientName, server string, ops ...Option) (privpb.BackendServer, io.Closer, error) {
	c, err := f.NewClient(clientName, server, ops...)
	if err != nil {
		return nil, nil, err
	}
	return privproxypb.NewBackendClient(c.Conn(), c.Opts()), c, nil
}
