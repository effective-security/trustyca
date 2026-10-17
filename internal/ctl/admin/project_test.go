package admin_test

import (
	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/ctl/admin"
)

func (s *testSuiteGrpc) Test_ProjectListCmd() {
	s.MockAdmin.SetResponse(&pb.ProjectsResponse{Projects: []*pb.Project{{ID: "1", Name: "P1", OrgID: "5"}}})
	cmd := &admin.ProjectListCmd{}
	err := cmd.Run(s.Ctl)
	s.Require().NoError(err)

	s.MockAdmin.Err = errors.New("something happened")
	defer func() { s.MockAdmin.Err = nil }()
	err = cmd.Run(s.Ctl)
	s.EqualError(err, "unexpected: something happened")
}
