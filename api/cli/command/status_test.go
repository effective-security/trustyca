package command_test

import (
	"github.com/effective-security/trustyca/api/cli/command"
)

func (s *testSuiteRest) TestVersion() {
	var a command.VersionCmd
	err := a.Run(s.Ctl)
	s.Require().NoError(err)
	s.CapturePrint()

	s.Ctl.O = "json"
	s.Out.Reset()

	err = a.Run(s.Ctl)
	s.Require().NoError(err)
	s.CapturePrint()
}

func (s *testSuiteRest) TestCaller() {
	var a command.CallerCmd
	err := a.Run(s.Ctl)
	s.Require().NoError(err)
	s.CapturePrint()

	s.Ctl.O = "json"
	s.Out.Reset()

	err = a.Run(s.Ctl)
	s.Require().NoError(err)
	s.CapturePrint()
}

func (s *testSuiteRest) TestServer() {
	var a command.ServerCmd
	err := a.Run(s.Ctl)
	s.Require().NoError(err)
	//s.CapturePrint()

	s.Ctl.O = "json"
	s.Out.Reset()

	err = a.Run(s.Ctl)
	s.Require().NoError(err)
	//s.CapturePrint()
}
