package ctl

import (
	"bytes"
	"net"
	"os"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/api/pb/mockpb"
	"github.com/effective-security/x/ctl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
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

	t.Run("after_apply", func(t *testing.T) {
		var cl struct {
			Cli
			Cmd struct{} `kong:"cmd"`
		}
		p := mustNew(t, &cl)
		_, err := p.Parse([]string{
			"cmd",
			"-D",
			"--server", "https://localhost:8880",
			"--timeout", "1",
			"--cfg", homeDir + "/.trustyca/cli/config.yaml",
			"--storage", "/tmp/trustyca/cli",
			"--cert-key", homeDir + "/.trustyca/certs/trustyca_client.key",
			"--trusted-ca", homeDir + "/.trustyca/certs/trusty_root_ca.pem",
		})
		assert.EqualError(t, err, "--cert-key option specified without --cert")
	})

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
			"--cfg", "/tmp/trustyca/cli/config.yaml",
			"--storage", "/tmp/trustyca/cli",
			"--cert", homeDir + "/.trustyca/certs/trustyca_client.pem",
			"--cert-key", homeDir + "/.trustyca/certs/trustyca_client.key",
			"--trusted-ca", homeDir + "/.trustyca/certs/trusty_root_ca.pem",
		})
		assert.NoError(t, err)
		require.Equal(t, "cmd", ctx.Command())

		_, err = cl.Cli.RPCClient(true)
		assert.EqualError(t, err, "unable to create client: failed to connect to \"localhost:8880\" within 6s")

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
			"--cfg", "/tmp/trustyca/cli/config.yaml",
			"--storage", "/tmp/trustyca/cli",
			"--cert", "~/.trustyca/certs/trustyca_client.pem",
			"--cert-key", "~/.trustyca/certs/trustyca_client.key",
			"--trusted-ca", "~/.trustyca/certs/trusty_root_ca.pem",
		})
		require.NoError(t, err)
		require.Equal(t, "cmd", ctx.Command())

		assert.False(t, cl.IsJSON())

		_, err = cl.Cli.RPCClient(true)
		assert.EqualError(t, err, "unable to create client: failed to connect to \"localhost:8880\" within 1s")

		_, err = cl.Cli.HTTPClient(true)
		assert.NoError(t, err)
		_, err = cl.Cli.HTTPClient(true)
		assert.NoError(t, err)
	})
}

func TestClients(t *testing.T) {
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
		"--cfg", "/tmp/trustyca/cli/config.yaml",
		"--storage", "/tmp/trustyca/cli",
		"--cert", "~/.trustyca/certs/trustyca_client.pem",
		"--cert-key", "~/.trustyca/certs/trustyca_client.key",
		"--trusted-ca", "~/.trustyca/certs/trusty_root_ca.pem",
	})
	require.NoError(t, err)
	require.Equal(t, "cmd", ctx.Command())

	_, err = cl.Cli.RPCClient(true)
	assert.NoError(t, err)

	cl.Cli.HTTP = true
	_, err = cl.Cli.HTTPClient(true)
	assert.NoError(t, err)
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

// func TestCallerIdentity(t *testing.T) {
// 	t.Setenv("AWS_ACCESS_KEY_ID", "")
// 	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
// 	t.Setenv("AWS_REGION", "")
// 	t.Setenv("AWS_DEFAULT_REGION", "")

// 	_, err := NewCallerIdentity()
// 	assert.EqualError(t, err, "AWS_ACCESS_KEY_ID and AWS_SECRET_KEY must be set to use --sts flag")

// 	t.Setenv("AWS_ACCESS_KEY_ID", "notused")
// 	t.Setenv("AWS_SECRET_ACCESS_KEY", "notused")
// 	_, err = NewCallerIdentity()
// 	assert.EqualError(t, err, "AWS_DEFAULT_REGION or AWS_REGION must be set to use --sts flag")

// 	t.Setenv("AWS_REGION", "eu-central-1")
// 	ci, err := NewCallerIdentity()
// 	require.NoError(t, err)

// 	ctrl := gomock.NewController(t)
// 	sts := mockaws.NewMockSTS(ctrl)
// 	sts.EXPECT().PresignGetCallerIdentity(gomock.Any(), gomock.Any(), gomock.Any()).Return(&credentials.Token{}, nil)
// 	sts.EXPECT().PresignGetCallerIdentity(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, errors.Errorf("sts failed"))

// 	ci.(*callerIdentity).sts = sts

// 	ctx := context.Background()
// 	_, err = ci.GetCallerIdentity(ctx)
// 	require.NoError(t, err)
// 	_, err = ci.GetCallerIdentity(ctx)
// 	assert.EqualError(t, err, "sts failed")
// }
