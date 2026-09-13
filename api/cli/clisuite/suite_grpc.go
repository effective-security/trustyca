package clisuite

import (
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/alecthomas/kong"
	"github.com/effective-security/trustyca/api/cli"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/api/pb/mockpb"
	"github.com/effective-security/x/ctl"
	"github.com/effective-security/x/format"
	"google.golang.org/grpc"
)

// TestSuiteGrpc provider test suite for RPC
type TestSuiteGrpc struct {
	TestSuite
	MockAuth   mockpb.MockAuthServer
	MockStatus mockpb.MockStatusServer
	MockOrgs   mockpb.MockOrgsServer
	RPCServer  *grpc.Server
}

// SetupSuite called once to setup
func (s *TestSuiteGrpc) SetupSuite() {
	pb.RegisterPrintOnce()

	s.Folder = filepath.Join(os.TempDir(), "test", "trustyca-grpcclient")

	s.Ctl = &cli.Cli{
		Version: "0.1.1",
		Storage: s.Folder,
	}

	s.Ctl.WithErrWriter(&s.Out).
		WithWriter(&s.Out)

	parser, err := kong.New(s.Ctl,
		kong.Name("trustyca-test"),
		kong.Description("trustyca test client"),
		kong.Writers(&s.Out, &s.Out),
		ctl.BoolPtrMapper,
		//kong.Exit(exit),
		kong.ConfigureHelp(kong.HelpOptions{
			Compact: true,
		}),
		kong.Vars{})
	if err != nil {
		s.FailNow("unexpected error constructing Kong: %+v", err)
	}

	s.RPCServer = s.SetupMockGRPC()

	_, err = parser.Parse([]string{"-s", s.Ctl.Server, "--storage", s.Folder})
	if err != nil {
		s.FailNow("unexpected error parsing: %+v", err)
	}
}

// TearDownSuite called once to destroy
func (s *TestSuiteGrpc) TearDownSuite() {
	s.RPCServer.Stop()

	s.TestSuite.TearDownSuite()
}

// SetupTest called before each test
func (s *TestSuiteGrpc) SetupTest() {
	s.Out.Reset()
	s.Ctl.O = ""
	format.NowFunc = func() time.Time {
		return time.Date(2024, 5, 6, 7, 8, 9, 0, time.UTC)
	}
}

// TearDownTest called after each test
func (s *TestSuiteGrpc) TearDownTest() {
	format.NowFunc = time.Now
}

// SetupMockGRPC for testing
func (s *TestSuiteGrpc) SetupMockGRPC() *grpc.Server {
	serv := grpc.NewServer()
	pb.RegisterAuthServer(serv, &s.MockAuth)
	pb.RegisterStatusServer(serv, &s.MockStatus)
	pb.RegisterOrgsServer(serv, &s.MockOrgs)
	var lis net.Listener
	var err error

	for i := 0; i < 5; i++ {
		addr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort("localhost", "0"))
		if err != nil {
			continue
		}
		s.T().Logf("%s: starting on %s", s.T().Name(), addr)

		lis, err = net.ListenTCP("tcp", addr)
		if err == nil {
			break
		}
		s.T().Logf("ERROR: %s: starting on %s, err=%v", s.T().Name(), addr, err)
	}
	s.Require().NoError(err)

	s.Ctl.Server = lis.Addr().String()

	go func() {
		_ = serv.Serve(lis)
	}()

	// allow to start
	//time.Sleep(1 * time.Second)
	return serv
}
