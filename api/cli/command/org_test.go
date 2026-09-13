package command_test

import (
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/trustyca/api/cli/command"
	"github.com/effective-security/trustyca/api/pb"
	"google.golang.org/grpc/codes"
)

func (s *testSuiteGrpc) Test_OrgCreateCmd() {
	expectedResponse := &pb.Org{
		ID:          "1",
		Name:        "Test Org",
		Description: "Test Description",
		Status:      pb.ItemStatus_Active,
	}

	s.MockOrgs.SetResponse(expectedResponse)
	a := command.OrgCreateCmd{}
	err := a.Run(s.Ctl)
	s.Require().NoError(err)
	s.CapturePrint()

	s.Ctl.O = "json"
	s.Out.Reset()

	err = a.Run(s.Ctl)
	s.Require().NoError(err)
	s.CapturePrint()

	s.MockOrgs.Err = httperror.NewGrpc(codes.Unknown, "request failed")
	err = a.Run(s.Ctl)
	s.EqualError(err, "unexpected: request failed")
}

func (s *testSuiteGrpc) Test_OrgUpdateCmd() {
	expectedResponse := &pb.Org{
		ID:          "1",
		Name:        "Test Org",
		Description: "Test Description",
		Status:      pb.ItemStatus_Active,
	}
	s.MockOrgs.SetResponse(expectedResponse)

	a := command.OrgUpdateCmd{}
	err := a.Run(s.Ctl)
	s.Require().NoError(err)
	s.CapturePrint()

	s.Ctl.O = "json"
	s.Out.Reset()

	err = a.Run(s.Ctl)
	s.Require().NoError(err)
	s.CapturePrint()

	s.MockOrgs.Err = httperror.NewGrpc(codes.Unknown, "request failed")
	err = a.Run(s.Ctl)
	s.EqualError(err, "unexpected: request failed")
}

func (s *testSuiteGrpc) Test_OrgDeleteCmd() {
	expectedResponse := &pb.Org{
		ID:          "1",
		Name:        "Test Org",
		Description: "Test Description",
		Status:      pb.ItemStatus_Inactive,
	}
	s.MockOrgs.SetResponse(expectedResponse)

	a := command.OrgDeleteCmd{}
	err := a.Run(s.Ctl)
	s.Require().NoError(err)
	s.CapturePrint()

	s.Ctl.O = "json"
	s.Out.Reset()

	err = a.Run(s.Ctl)
	s.Require().NoError(err)
	s.CapturePrint()

	s.MockOrgs.Err = httperror.NewGrpc(codes.Unknown, "request failed")
	err = a.Run(s.Ctl)
	s.EqualError(err, "unexpected: request failed")
}

func (s *testSuiteGrpc) Test_OrgGetCmd() {
	expectedResponse := &pb.Org{
		ID:          "1",
		Name:        "Test Org",
		Description: "Test Description",
		Status:      pb.ItemStatus_Inactive,
	}
	s.MockOrgs.SetResponse(expectedResponse)

	a := command.OrgGetCmd{}
	err := a.Run(s.Ctl)
	s.Require().NoError(err)
	s.CapturePrint()

	s.Ctl.O = "json"
	s.Out.Reset()

	err = a.Run(s.Ctl)
	s.Require().NoError(err)
	s.CapturePrint()

	s.MockOrgs.Err = httperror.NewGrpc(codes.Unknown, "request failed")
	err = a.Run(s.Ctl)
	s.EqualError(err, "unexpected: request failed")
}

func (s *testSuiteGrpc) Test_OrgListCmd() {
	expectedResponse := &pb.UserOrgsResponse{
		Orgs: []*pb.OrgAccess{
			{
				OrgID:        "1",
				OrgName:      "Test Org",
				Role:         pb.Role_Admin,
				RoleSource:   pb.RoleSource_Direct,
				ExplicitRole: pb.Role_Admin,
			},
			{
				OrgID:      "2",
				OrgName:    "Other Org",
				Role:       pb.Role_Viewer,
				RoleSource: pb.RoleSource_Project,
			},
		},
	}
	s.MockOrgs.SetResponse(expectedResponse)

	a := command.OrgListCmd{}
	err := a.Run(s.Ctl)
	s.Require().NoError(err)
	s.CapturePrint()

	s.Ctl.O = "json"
	s.Out.Reset()

	err = a.Run(s.Ctl)
	s.Require().NoError(err)
	s.CapturePrint()

	s.MockOrgs.Err = httperror.NewGrpc(codes.Unknown, "request failed")
	err = a.Run(s.Ctl)
	s.EqualError(err, "unexpected: request failed")
}

func (s *testSuiteGrpc) Test_OrgAccessCmd() {
	s.MockOrgs.SetResponse(&pb.UserMemberships{
		Org: &pb.OrgAccess{
			OrgID:      "1",
			OrgName:    "Test Org",
			Role:       pb.Role_Viewer,
			RoleSource: pb.RoleSource_Project,
		},
		Memberships: []*pb.Membership{
			{
				ID:           "1",
				OrgID:        "1",
				ProjectID:    "201",
				ProjectAlias: "payments",
				Scope:        pb.Scope_Project,
				Role:         pb.Role_Admin,
			},
		},
	})
	a := command.OrgAccessCmd{}
	err := a.Run(s.Ctl)
	s.Require().NoError(err)
	s.CapturePrint()

	s.Ctl.O = "json"
	s.Out.Reset()

	err = a.Run(s.Ctl)
	s.Require().NoError(err)
	s.CapturePrint()

	s.MockOrgs.Err = httperror.NewGrpc(codes.Unknown, "request failed")
	err = a.Run(s.Ctl)
	s.EqualError(err, "unexpected: request failed")
}
