package cli

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/alecthomas/kong"
	"github.com/effective-security/porto/pkg/retriable"
	"github.com/effective-security/porto/pkg/tlsconfig"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/api/pb/mockpb"
	"github.com/effective-security/x/ctl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestContext(t *testing.T) {
	var c Cli

	assert.NotNil(t, c.ErrWriter())
	assert.NotNil(t, c.Writer())
	assert.NotNil(t, c.Reader())

	c.WithErrWriter(os.Stderr)
	c.WithReader(os.Stdin)
	c.WithWriter(os.Stdout)

	assert.NotNil(t, c.ErrWriter())
	assert.NotNil(t, c.Writer())
	assert.NotNil(t, c.Reader())
	assert.NotNil(t, c.Context())

	v := &pb.ServerVersion{
		Build:   "1.2.3",
		Runtime: "go 1.20",
	}

	out := bytes.NewBuffer([]byte{})
	c.WithWriter(out)
	c.O = "json"
	err := c.Print(v)
	require.NoError(t, err)
	assert.Equal(t, "{\n\t\"Build\": \"1.2.3\",\n\t\"Runtime\": \"go 1.20\"\n}\n", out.String())

	out.Reset()
	c.O = "yaml"
	err = c.Print(v)
	require.NoError(t, err)
	assert.Equal(t, "build: 1.2.3\nruntime: go 1.20\n", out.String())
}

func TestParse(t *testing.T) {
	homeDir := os.Getenv("HOME")
	require.NotEmpty(t, homeDir, "HOME is not set")

	t.Run("parse_no_server", func(t *testing.T) {
		t.Setenv("TRUSTYCA_SERVER", "https://localhost:8880")
		var cl struct {
			Cli
			Cmd struct{} `kong:"cmd"`
		}
		p := mustNew(t, &cl)
		ctx, err := p.Parse([]string{
			"cmd",
			"--server", "",
			"--cfg", homeDir + "/.trustyca/cli/config.yaml",
			"--storage", homeDir + "/.trustyca/cli",
			//"--trusted-ca", homeDir + "/.trustyca/certs/trustyca_root.pem",
		})
		assert.NoError(t, err)
		require.Equal(t, "cmd", ctx.Command())

		_, err = cl.Cli.RPCClient(true)
		assert.EqualError(t, err, "unable to create client: failed to connect to \"localhost:8880\": context deadline exceeded")

		_, err = cl.Cli.HTTPClient(true)
		assert.NoError(t, err)
	})

	t.Run("parse", func(t *testing.T) {
		var cl struct {
			Cli
			Cmd struct{} `kong:"cmd"`
		}
		p := mustNew(t, &cl)
		ctx, err := p.Parse([]string{
			"cmd",
			"--server", "https://localhost:8880",
			"--timeout", "1",
			"--cfg", homeDir + "/.trustyca/cli/config.yaml",
			"--storage", homeDir + "/.trustyca/cli",
			//"--trusted-ca", homeDir + "/.trustyca/certs/trustyca_root.pem",
		})
		require.NoError(t, err)
		require.Equal(t, "cmd", ctx.Command())

		assert.False(t, cl.IsJSON())

		_, err = cl.Cli.RPCClient(true)
		assert.EqualError(t, err, "unable to create client: failed to connect to \"localhost:8880\": context deadline exceeded")

		_, err = cl.Cli.HTTPClient(true)
		assert.NoError(t, err)
		_, err = cl.Cli.HTTPClient(true)
		assert.NoError(t, err)
	})
}

func TestClients(t *testing.T) {
	homeDir := os.Getenv("HOME")
	require.NotEmpty(t, homeDir, "HOME is not set")

	var mockStatus mockpb.MockStatusServer
	serv := grpc.NewServer()
	pb.RegisterStatusServer(serv, &mockStatus)

	var lis net.Listener
	var err error

	addr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort("localhost", "0"))
	require.NoError(t, err)

	lis, err = net.ListenTCP("tcp", addr)
	require.NoError(t, err)

	go func() {
		_ = serv.Serve(lis)
	}()
	defer serv.Stop()

	var cl struct {
		Cli
		Cmd struct{} `kong:"cmd"`
	}
	p := mustNew(t, &cl)
	ctx, err := p.Parse([]string{
		"cmd",
		"--server", lis.Addr().String(),
		"--timeout", "1",
		"--cfg", homeDir + "/.trustyca/cli/config.yaml",
		"--storage", homeDir + "/.trustyca/cli",
		//"--trusted-ca", homeDir + "/.trustyca/certs/trustyca_root.pem",
	})
	require.NoError(t, err)
	require.Equal(t, "cmd", ctx.Command())

	_, err = cl.Cli.RPCClient(true)
	assert.NoError(t, err)
	_, err = cl.Cli.StatusClient()
	assert.NoError(t, err)
	_, err = cl.Cli.OrgsClient()
	assert.NoError(t, err)
	_, err = cl.Cli.CISClient()
	assert.NoError(t, err)

	cl.Cli.HTTP = true
	_, err = cl.Cli.HTTPClient(true)
	assert.NoError(t, err)
	_, err = cl.Cli.StatusClient()
	assert.NoError(t, err)
	_, err = cl.Cli.OrgsClient()
	assert.NoError(t, err)
	_, err = cl.Cli.CISClient()
	assert.NoError(t, err)
}

// TestRPCClient_StoredToken checks that the gRPC client sends the token of
// the storage folder to a server the config file does not list, as the HTTP
// client does: `auth login -s <server>` stores it there
func TestRPCClient_StoredToken(t *testing.T) {
	homeDir := os.Getenv("HOME")
	require.NotEmpty(t, homeDir, "HOME is not set")
	certs := filepath.Join(homeDir, ".trustyca", "certs")

	tlsCfg, err := tlsconfig.NewServerTLSFromFiles(
		filepath.Join(certs, "trustyca_server.pem"),
		filepath.Join(certs, "trustyca_server.key"),
		"", "", tls.NoClientCert)
	require.NoError(t, err)

	var (
		lock          sync.Mutex
		authorization []string
	)
	mockStatus := &mockpb.MockStatusServer{}
	mockStatus.SetResponse(&pb.ServerVersion{Build: "1.2.3"})
	serv := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsCfg)),
		grpc.UnaryInterceptor(func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
			md, _ := metadata.FromIncomingContext(ctx)
			lock.Lock()
			authorization = append(authorization, md.Get("authorization")...)
			lock.Unlock()
			return handler(ctx, req)
		}),
	)
	pb.RegisterStatusServer(serv, mockStatus)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() {
		_ = serv.Serve(lis)
	}()
	defer serv.Stop()

	storage := t.TempDir()
	token := url.Values{
		"access_token": {"stored-token"},
		"exp":          {strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)},
	}
	_, err = retriable.NewStorage(storage).SaveAuthToken(token.Encode())
	require.NoError(t, err)

	var cl struct {
		Cli
		Cmd struct{} `kong:"cmd"`
	}
	p := mustNew(t, &cl)
	_, err = p.Parse([]string{
		"cmd",
		// the default config file lists https://localhost:8880 only
		"--server", "https://localhost:" + strconv.Itoa(lis.Addr().(*net.TCPAddr).Port),
		"--timeout", "5",
		"--cfg", filepath.Join(storage, "config.yaml"),
		"--storage", storage,
		"--trusted-ca", filepath.Join(certs, "trustyca_root.pem"),
	})
	require.NoError(t, err)

	// the client of the authenticated commands
	rc, err := cl.Cli.RPCClient(false)
	require.NoError(t, err)
	res, err := pb.NewStatusClient(rc.Conn()).Version(cl.Cli.Context(), &emptypb.Empty{})
	require.NoError(t, err)
	assert.Equal(t, "1.2.3", res.Build)

	lock.Lock()
	defer lock.Unlock()
	assert.Equal(t, []string{"Bearer stored-token"}, authorization)
}

func mustNew(t *testing.T, cli any, options ...kong.Option) *kong.Kong {
	t.Helper()
	options = append([]kong.Option{
		kong.Name("test"),
		kong.Exit(func(int) {
			t.Helper()
			t.Fatalf("unexpected exit()")
		}),
		ctl.BoolPtrMapper,
	}, options...)
	parser, err := kong.New(cli, options...)
	require.NoError(t, err)

	return parser
}
