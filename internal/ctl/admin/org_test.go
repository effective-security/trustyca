package admin_test

import (
	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/ctl/admin"
)

func ctlOrg() *pb.Org {
	return &pb.Org{
		ID:     "5",
		Alias:  "ba_corp",
		Name:   "Corp",
		Status: pb.ItemStatus_Active,
	}
}

func (s *testSuiteGrpc) Test_OrgListCmd() {
	s.MockAdmin.SetResponse(&pb.OrgsResponse{Orgs: []*pb.Org{ctlOrg()}})
	cmd := &admin.OrgListCmd{Status: "Active", Limit: 10, Cursor: "initial"}
	err := cmd.Run(s.Ctl)
	s.Require().NoError(err)

	cmd.Status = "Nope"
	err = cmd.Run(s.Ctl)
	s.EqualError(err, "invalid status: Nope")

	cmd.Status = ""
	s.MockAdmin.Err = errors.New("something happened")
	defer func() { s.MockAdmin.Err = nil }()
	err = cmd.Run(s.Ctl)
	s.EqualError(err, "unexpected: something happened")
}

/*
func (s *testSuiteGrpc) Test_OrgGetCmd() {
	s.MockAdmin.SetResponse(ctlOrg())
	cmd := &admin.OrgGetCmd{Org: "5"}
	err := cmd.Run(s.Ctl)
	s.Require().NoError(err)

	s.MockAdmin.Err = errors.New("something happened")
	defer func() { s.MockAdmin.Err = nil }()
	err = cmd.Run(s.Ctl)
	s.EqualError(err, "unexpected: something happened")
}

func (s *testSuiteGrpc) Test_OrgCreateCmd() {
	s.MockAdmin.SetResponse(ctlOrg())
	cmd := &admin.OrgCreateCmd{Owner: "owner@example.com", Name: "Corp", TaxID: []string{"eu_vat=DE123"}}
	cmd.Country = "DE"
	err := cmd.Run(s.Ctl)
	s.Require().NoError(err)

	cmd.TaxID = []string{"nope"}
	err = cmd.Run(s.Ctl)
	s.EqualError(err, `invalid tax id "nope": expected type=value`)

	cmd.TaxID = nil
	s.MockAdmin.Err = errors.New("something happened")
	defer func() { s.MockAdmin.Err = nil }()
	err = cmd.Run(s.Ctl)
	s.EqualError(err, "unexpected: something happened")
}

func (s *testSuiteGrpc) Test_OrgUpdateCmd() {
	s.MockAdmin.SetResponse(ctlOrg())
	cmd := &admin.OrgUpdateCmd{Org: "5", Name: "Corp Inc", Status: "Inactive"}
	err := cmd.Run(s.Ctl)
	s.Require().NoError(err)

	cmd.Status = "Nope"
	err = cmd.Run(s.Ctl)
	s.EqualError(err, "invalid status")

	cmd.Status = ""
	s.MockAdmin.Err = errors.New("something happened")
	defer func() { s.MockAdmin.Err = nil }()
	err = cmd.Run(s.Ctl)
	s.EqualError(err, "unexpected: something happened")
}

func (s *testSuiteGrpc) Test_OrgDisableEnableCmd() {
	disabled := ctlOrg()
	disabled.Status = pb.ItemStatus_Disabled
	s.MockAdmin.SetResponse(&privpb.OrganizationStatusResponse{Organization: disabled, Projects: 2, VirtualKeys: 3})
	err := (&admin.OrgDisableCmd{Org: "5", Reason: "ToS 4.2"}).Run(s.Ctl)
	s.Require().NoError(err)

	s.MockAdmin.SetResponse(&privpb.OrganizationStatusResponse{Organization: ctlOrg(), Projects: 2, VirtualKeys: 3})
	err = (&admin.OrgEnableCmd{Org: "5"}).Run(s.Ctl)
	s.Require().NoError(err)

	s.MockAdmin.Err = errors.New("something happened")
	defer func() { s.MockAdmin.Err = nil }()
	err = (&admin.OrgDisableCmd{Org: "5"}).Run(s.Ctl)
	s.EqualError(err, "unexpected: something happened")
	err = (&admin.OrgEnableCmd{Org: "5"}).Run(s.Ctl)
	s.EqualError(err, "unexpected: something happened")
}

func (s *testSuiteGrpc) Test_OrgDeleteCmd() {
	s.MockAdmin.SetResponse(&emptypb.Empty{})
	cmd := &admin.OrgDeleteCmd{Org: "5"}
	err := cmd.Run(s.Ctl)
	s.Require().NoError(err)

	s.MockAdmin.Err = errors.New("something happened")
	defer func() { s.MockAdmin.Err = nil }()
	err = cmd.Run(s.Ctl)
	s.EqualError(err, "unexpected: something happened")
}

func (s *testSuiteGrpc) Test_OrgProjectListCmd() {
	s.MockAdmin.SetResponse(&pb.ProjectsResponse{Projects: []*pb.Project{{ID: "1", Name: "P1", OrgID: "5"}}})
	cmd := &admin.OrgProjectListCmd{Org: "5"}
	err := cmd.Run(s.Ctl)
	s.Require().NoError(err)

	s.MockAdmin.Err = errors.New("something happened")
	defer func() { s.MockAdmin.Err = nil }()
	err = cmd.Run(s.Ctl)
	s.EqualError(err, "unexpected: something happened")
}
*/
