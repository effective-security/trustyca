package command_test

import (
	"testing"

	"github.com/effective-security/trustyca/api/cli/clisuite"
	"github.com/stretchr/testify/suite"
)

type testSuiteRest struct {
	clisuite.TestSuite
}

func TestSuite(t *testing.T) {
	t.Parallel()
	suite.Run(t, new(testSuiteRest))
}

type testSuiteGrpc struct {
	clisuite.TestSuiteGrpc
}

func TestRpc(t *testing.T) {
	t.Parallel()
	suite.Run(t, new(testSuiteGrpc))
}
