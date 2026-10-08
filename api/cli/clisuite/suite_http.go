package clisuite

import (
	"bytes"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"github.com/alecthomas/kong"
	"github.com/effective-security/servefiles"
	"github.com/effective-security/trustyca/api/cli"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/api/version"
	"github.com/effective-security/trustyca/tests/testutils"
	xctl "github.com/effective-security/x/ctl"
	"github.com/effective-security/x/values"
	"github.com/stretchr/testify/suite"
)

// serverPlaceholder replaces the address of the suite's mock server in
// captured output, since the server may listen on an ephemeral port
const serverPlaceholder = "{server}"

// TestSuite provides suite for testing HTTP
type TestSuite struct {
	suite.Suite

	// Server is file based Server
	Server *servefiles.Server

	Folder string
	Ctl    *cli.Cli
	// Out is the outpub buffer
	Out bytes.Buffer

	// goldenFile holds the expected output of CapturePrint, one file per
	// suite: testdata/prints_<suite test>.txt
	goldenFile   string
	printResults []testutils.GoldenEntry
	lock         sync.Mutex
}

// CapturePrint records the output of the current test, to be compared with
// the suite's golden file in TearDownSuite. The address of the mock server
// is replaced with a placeholder. A test may capture more than once.
func (s *TestSuite) CapturePrint() {
	s.lock.Lock()
	defer s.lock.Unlock()
	ext := values.StringsCoalesce(s.Ctl.O, "txt")
	out := s.Out.String()
	if host := serverHost(s.Ctl.Server); host != "" {
		out = strings.ReplaceAll(out, host, serverPlaceholder)
	}

	s.printResults = append(s.printResults, testutils.GoldenEntry{
		Name: testutils.UniqueGoldenName(s.printResults, s.T().Name()+"/"+ext),
		Out:  out,
	})
}

// serverHost returns the host and port of a server address, which is a URL
// for the HTTP suite and host:port for the gRPC suite
func serverHost(server string) string {
	if u, err := url.Parse(server); err == nil && u.Host != "" {
		return u.Host
	}
	return server
}

// setGoldenFile names the golden file after the suite's test
func (s *TestSuite) setGoldenFile() {
	s.goldenFile = filepath.Join("testdata", "prints_"+s.T().Name()+".txt")
}

// HasNoText is a helper method to assert that the out stream does contains the supplied
// text somewhere
func (s *TestSuite) HasNoText(texts ...string) {
	outStr := s.Out.String()
	for _, t := range texts {
		s.Contains(outStr, t)
	}
}

// SetupSuite called once to setup
func (s *TestSuite) SetupSuite() {
	pb.RegisterPrintOnce()
	s.setGoldenFile()

	s.Folder = path.Join(os.TempDir(), "test", "trustyca-client")

	s.Ctl = &cli.Cli{
		Version: xctl.VersionFlag(version.Current().String()),
		Storage: s.Folder,
	}

	s.Ctl.WithErrWriter(&s.Out).
		WithWriter(&s.Out)

	s.Server = servefiles.New(s.T())
	s.Server.SetBaseDirs("../testdata")
	s.Ctl.Server = s.Server.URL()

	parser, err := kong.New(s.Ctl,
		kong.Name("trustyca-test"),
		kong.Description("trustyca test client"),
		kong.Writers(&s.Out, &s.Out),
		xctl.BoolPtrMapper,
		//kong.Exit(exit),
		kong.ConfigureHelp(kong.HelpOptions{
			Compact: true,
		}),
		kong.Vars{})
	if err != nil {
		s.FailNow("unexpected error constructing Kong: %+v", err)
	}

	_, err = parser.Parse([]string{
		"-s", s.Server.URL(),
		"-H", // use HTTP
		"--storage", s.Folder,
		"--cfg", path.Join(s.Folder, "config.yaml"),
	})
	if err != nil {
		s.FailNow("unexpected error parsing: %+v", err)
	}
}

// TearDownSuite called once to destroy. It compares the captured output
// with the golden file; see testutils.CheckGolden for the update mode.
func (s *TestSuite) TearDownSuite() {
	testutils.CheckGolden(s.T(), s.goldenFile, s.printResults)

	if s.Server != nil {
		s.Server.Close()
	}
	os.RemoveAll(s.Folder)
}

// SetupTest called before each test
func (s *TestSuite) SetupTest() {
	s.Out.Reset()
	s.Ctl.O = ""
}

// TearDownTest called after each test
func (s *TestSuite) TearDownTest() {
}
