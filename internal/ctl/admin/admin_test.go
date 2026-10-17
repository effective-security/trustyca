package admin_test

import (
	"testing"

	"github.com/effective-security/trustyca/internal/ctl/ctlsuite"
	"github.com/stretchr/testify/suite"
)

type testSuiteGrpc struct {
	ctlsuite.TestSuiteGrpc
}

func TestRpc(t *testing.T) {
	suite.Run(t, new(testSuiteGrpc))
}
