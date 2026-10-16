package command_test

import (
	"testing"

	"github.com/effective-security/trustyca/api/cli/clisuite"
	"github.com/stretchr/testify/suite"
)

type testSuiteRest struct {
	clisuite.TestSuite
}

// The suites are not parallel: parsing the CLI configuration sets
// process-wide logging and time formatting, Cli.AfterApply, and the gRPC
// suite replaces format.NowFunc for each test.
func TestSuite(t *testing.T) {
	suite.Run(t, new(testSuiteRest))
}

type testSuiteGrpc struct {
	clisuite.TestSuiteGrpc
}

func TestRpc(t *testing.T) {
	suite.Run(t, new(testSuiteGrpc))
}
