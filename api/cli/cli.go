package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/alecthomas/kong"
	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/pkg/retriable"
	"github.com/effective-security/porto/pkg/rpcclient"
	"github.com/effective-security/porto/pkg/tlsconfig"
	"github.com/effective-security/porto/xhttp/correlation"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/api/pb/proxypb"
	"github.com/effective-security/trustyca/api/version"
	"github.com/effective-security/x/ctl"
	"github.com/effective-security/x/fileutil/resolve"
	"github.com/effective-security/x/format"
	"github.com/effective-security/x/print"
	"github.com/effective-security/x/values"
	"github.com/effective-security/xlog"
	"github.com/mitchellh/go-homedir"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/trustyca/api", "cli")

var (
	// DefaultStoragePath specifies default storage path
	DefaultStoragePath = "~/.config/trustyca"

	ServerAlias = map[string]string{
		"local": "https://localhost:7880",
		"dev":   "https://wfe.dev.trustyca.io",
		"prod":  "https://wfe.prod.trustyca.io",
	}
)

// Cli provides CLI context to run commands
type Cli struct {
	Server  string          `short:"s" help:"Address of the remote server to connect.  Use TRUSTYCA_SERVER environment to override"`
	Debug   bool            `short:"D" help:"Enable debug mode"`
	Version ctl.VersionFlag `name:"version" help:"Print version information and quit" hidden:""`
	O       string          `help:"Print output format: json|yaml"`
	Cfg     string          `help:"Configuration file" default:"~/.config/trustyca/config.yaml"`
	Storage string          `help:"flag specifies to override default location: ~/.config/trustyca. Use TRUSTYCA_STORAGE environment to override"`
	HTTP    bool            `short:"H" help:"Use HTTP client"`

	TimeFormat string `name:"time" help:"Print time format: utc|local|ago" hidden:"" default:"utc"`

	Timeout   int    `help:"Connection timeout"  default:"6"`
	TrustedCA string `short:"r" help:"Trusted CA store for server TLS"`

	// Stdin is the source to read from, typically set to os.Stdin
	stdin io.Reader
	// Output is the destination for all output from the command, typically set to os.Stdout
	output io.Writer
	// ErrOutput is the destination for errors.
	// If not set, errors will be written to os.StdError
	errOutput io.Writer

	rpcClient  *rpcclient.Client
	httpClient *retriable.Client
	ctx        context.Context
}

// Context for requests
func (c *Cli) Context() context.Context {
	if c.ctx == nil {
		c.ctx = correlation.WithMetaFromContext(context.Background())
		logger.ContextKV(c.ctx, xlog.DEBUG, "context", "created")
	}
	return c.ctx
}

// IsJSON returns true if the output format us JSON
func (c *Cli) IsJSON() bool {
	return c.O == "json"
}

// Reader is the source to read from, typically set to os.Stdin
func (c *Cli) Reader() io.Reader {
	if c.stdin != nil {
		return c.stdin
	}
	return os.Stdin
}

// WithReader allows to specify a custom reader
func (c *Cli) WithReader(reader io.Reader) *Cli {
	c.stdin = reader
	return c
}

// Writer returns a writer for control output
func (c *Cli) Writer() io.Writer {
	if c.output != nil {
		return c.output
	}
	return os.Stdout
}

// WithWriter allows to specify a custom writer
func (c *Cli) WithWriter(out io.Writer) *Cli {
	c.output = out
	return c
}

// ErrWriter returns a writer for control output
func (c *Cli) ErrWriter() io.Writer {
	if c.errOutput != nil {
		return c.errOutput
	}
	return os.Stderr
}

// WithErrWriter allows to specify a custom error writer
func (c *Cli) WithErrWriter(out io.Writer) *Cli {
	c.errOutput = out
	return c
}

// // WithHTTPClient allows to specify an http client
// func (c *Cli) WithHTTPClient(httpClient *httpclient.Client) *Cli {
// 	c.httpClient = httpClient
// 	return c
// }

// AfterApply hook loads config
func (c *Cli) AfterApply(app *kong.Kong, vars kong.Vars) error {
	xlog.SetFormatter(xlog.NewPrettyFormatter(c.ErrWriter()))
	if c.Debug {
		xlog.SetGlobalLogLevel(xlog.DEBUG)
	} else {
		xlog.SetGlobalLogLevel(xlog.ERROR)
	}

	format.DefaultTimePrintFormat = c.TimeFormat

	if c.Server != "" && ServerAlias[c.Server] != "" {
		c.Server = ServerAlias[c.Server]
	}
	pb.RegisterPrintOnce()
	return nil
}

// RPCClient returns gRPC client
func (c *Cli) RPCClient(skipAuth bool) (*rpcclient.Client, error) {
	if c.rpcClient != nil {
		return c.rpcClient, nil
	}

	host := values.StringsCoalesce(c.Server, os.Getenv("TRUSTYCA_SERVER"))
	if host == "" {
		return nil, errors.New("no server specified. Use -s flag or TRUSTYCA_SERVER env var")
	}

	var err error

	storage := values.StringsCoalesce(
		c.Storage,
		os.Getenv("TRUSTYCA_STORAGE"),
		DefaultStoragePath,
	)

	timeout := time.Duration(c.Timeout) * time.Second
	clientCfg := &rpcclient.Config{
		DialTimeout:          timeout,
		DialKeepAliveTimeout: timeout,
		DialKeepAliveTime:    timeout,
		Endpoint:             host,
		UserAgent:            fmt.Sprintf("trustyca %s", version.Current().String()),
		StorageFolder:        storage,
	}

	if strings.HasPrefix(host, "https://") {
		ca := resolve.ExpandPath(c.TrustedCA)
		cfg := resolve.ExpandPath(c.Cfg)
		f, err := retriable.LoadFactory(cfg)
		if err == nil {
			rc := f.ConfigForHost(host)
			if rc != nil {
				storage := values.StringsCoalesce(
					c.Storage,
					os.Getenv("TRUSTYCA_STORAGE"),
					rc.StorageFolder,
					DefaultStoragePath,
				)
				clientCfg.StorageFolder, _ = homedir.Expand(storage)

				if rc.TLS != nil {
					ca = values.StringsCoalesce(ca, rc.TLS.TrustedCAFile)
				}

				if !skipAuth {
					err = clientCfg.LoadAuthTokenOrFromEnv("TRUSTYCA_AUTH_TOKEN")
					if err != nil {
						return nil, errors.WithMessage(err, "unable to load auth token")
					}
				}
			}
		}

		if ca != "" {
			logger.KV(xlog.DEBUG, "tls-trusted-ca", ca)
		}

		clientCfg.TLS, err = tlsconfig.NewClientTLSFromFiles("", "", ca)
		if err != nil {
			return nil, errors.WithMessage(err, "unable to build TLS configuration")
		}
	}

	grpcClient, err := rpcclient.New(clientCfg)
	if err != nil {
		return nil, errors.WithMessage(err, "unable to create client")
	}
	c.rpcClient = grpcClient

	// TODO: add Timeout and retries
	c.ctx = c.Context()

	return c.rpcClient, nil
}

// HTTPClient returns client
func (c *Cli) HTTPClient(skipAuth bool) (*retriable.Client, error) {
	if c.httpClient != nil {
		return c.httpClient, nil
	}

	server := values.StringsCoalesce(c.Server, os.Getenv("TRUSTYCA_SERVER"))
	if server == "" {
		return nil, errors.New("no server specified. Use -s flag or TRUSTYCA_SERVER env var")
	}

	cfg := resolve.ExpandPath(c.Cfg)

	client, err := retriable.NewForHost(cfg, server)
	if err != nil {
		return nil, err
	}

	// expand Storage in order of priorities: flag, Env, config, default
	storage := values.StringsCoalesce(
		c.Storage,
		os.Getenv("TRUSTYCA_STORAGE"),
		client.Config.StorageFolder,
		DefaultStoragePath,
	)

	c.Storage, _ = homedir.Expand(storage)
	client.Config.StorageFolder = c.Storage

	if strings.HasPrefix(server, "https://") {
		if c.TrustedCA != "" {
			ca := resolve.ExpandPath(c.TrustedCA)
			logger.KV(xlog.DEBUG, "tls-trusted-ca", ca)
			tlscfg, err := tlsconfig.NewClientTLSFromFiles(
				"",
				"",
				ca)
			if err != nil {
				return nil, errors.WithMessage(err, "unable to build TLS configuration")
			}
			client.WithTLS(tlscfg)
		}

		if !skipAuth {
			err = client.Config.LoadAuthTokenOrFromEnv("TRUSTYCA_AUTH_TOKEN")
			if err != nil {
				return nil, err
			}
			err = client.SetAuthorization()
			if err != nil {
				return nil, err
			}
		}
	}

	if c.Timeout > 0 {
		client.WithTimeout(time.Second * time.Duration(c.Timeout))
	}

	c.httpClient = client.WithUserAgent("trustyca " + version.Current().String())
	return c.httpClient, nil
}

// StatusClient returns StatusClient client from connection
func (c *Cli) StatusClient() (pb.StatusServer, error) {
	if c.HTTP {
		h, err := c.HTTPClient(true)
		if err != nil {
			return nil, err
		}
		return proxypb.NewHTTPStatusClient(h), nil
	}
	r, err := c.RPCClient(true)
	if err != nil {
		return nil, err
	}
	return proxypb.NewStatusClient(r.Conn(), r.Opts()), nil
}

// OrgsClient returns Orgs client from connection
func (c *Cli) OrgsClient() (pb.OrgsServer, error) {
	if c.HTTP {
		h, err := c.HTTPClient(false)
		if err != nil {
			return nil, err
		}
		return proxypb.NewHTTPOrgsClient(h), nil
	}
	r, err := c.RPCClient(false)
	if err != nil {
		return nil, err
	}
	return proxypb.NewOrgsClient(r.Conn(), r.Opts()), nil
}

// AuthClient returns AuthClient client from connection
func (c *Cli) AuthClient(skipAuth bool) (pb.AuthServer, error) {
	if c.HTTP {
		h, err := c.HTTPClient(skipAuth)
		if err != nil {
			return nil, err
		}
		return proxypb.NewHTTPAuthClient(h), nil
	}

	r, err := c.RPCClient(skipAuth)
	if err != nil {
		return nil, err
	}
	return proxypb.NewAuthClient(r.Conn(), r.Opts()), nil
}

// Print response to out
func (c *Cli) Print(value any) error {
	print.Object(c.Writer(), c.O, value)
	return nil
}

func (c *Cli) StringPrompt(label string) string {
	var s string
	bufferSize := 8192

	r := bufio.NewReaderSize(c.Reader(), bufferSize)
	w := c.Writer()
	for {
		fmt.Fprint(w, label+" ")
		s, _ = r.ReadString('\n')
		if s != "" {
			break
		}
	}

	return s
}
