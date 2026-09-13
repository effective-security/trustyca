package ctlsuite

import (
	"bytes"
	"os"
	"path"
	"path/filepath"
	"sort"
	"sync"

	"github.com/alecthomas/kong"
	"github.com/effective-security/servefiles"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/api/version"
	"github.com/effective-security/trustyca/internal/ctl"
	xctl "github.com/effective-security/x/ctl"
	"github.com/effective-security/x/values"
	"github.com/stretchr/testify/suite"
)

type printResult struct {
	name string
	out  string
}

// TestSuite provides suite for testing HTTP
type TestSuite struct {
	suite.Suite

	// Server is file based Server
	Server *servefiles.Server

	Folder string
	Ctl    *ctl.Cli
	// Out is the outpub buffer
	Out bytes.Buffer

	printResults []printResult
	lock         sync.Mutex
}

func (s *TestSuite) CapturePrint() {
	s.lock.Lock()
	defer s.lock.Unlock()
	ext := values.StringsCoalesce(s.Ctl.O, "txt")

	s.printResults = append(s.printResults, printResult{
		name: s.T().Name() + "/" + ext,
		out:  s.Out.String(),
	})
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

	s.Folder = path.Join(os.TempDir(), "test", "trustyca-client")

	s.Ctl = &ctl.Cli{
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

// TearDownSuite called once to destroy
func (s *TestSuite) TearDownSuite() {
	sort.Slice(s.printResults, func(i, j int) bool {
		return s.printResults[i].name < s.printResults[j].name
	})

	tmp := "testdata" //filepath.Join(os.TempDir(), "testdata")
	_ = os.Mkdir(tmp, 0755)
	f, err := os.Create(filepath.Join(tmp, "prints.txt"))
	s.Require().NoError(err)
	for _, r := range s.printResults {
		_, _ = f.WriteString("- ")
		_, _ = f.WriteString(r.name)
		_, _ = f.WriteString(":\n")
		_, _ = f.WriteString(r.out)
		_, _ = f.WriteString("\n")
	}
	_ = f.Close()

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
