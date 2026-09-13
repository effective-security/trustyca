package command_test

import (
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/trustyca/api/cli/command"
	"github.com/effective-security/trustyca/api/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/emptypb"
)

var testProject = &pb.Project{
	ID:          "201",
	OrgID:       "100",
	Alias:       "payments",
	Name:        "Payments",
	Description: "Payments project",
	Status:      pb.ItemStatus_Active,
}

func (s *testSuiteGrpc) runPrinted(run func() error) {
	err := run()
	s.Require().NoError(err)
	s.CapturePrint()

	s.Ctl.O = "json"
	s.Out.Reset()

	err = run()
	s.Require().NoError(err)
	s.CapturePrint()

	s.MockOrgs.Err = httperror.NewGrpc(codes.Unknown, "request failed")
	err = run()
	s.EqualError(err, "unexpected: request failed")
}

func (s *testSuiteGrpc) Test_ProjectCreateCmd() {
	s.MockOrgs.SetResponse(testProject)
	a := command.ProjectCreateCmd{Name: "Payments", Alias: "payments"}
	s.runPrinted(func() error { return a.Run(s.Ctl) })
}

func (s *testSuiteGrpc) Test_ProjectUpdateCmd() {
	s.MockOrgs.SetResponse(testProject)
	a := command.ProjectUpdateCmd{Project: "201", Name: "Payments"}
	s.runPrinted(func() error { return a.Run(s.Ctl) })
}

func (s *testSuiteGrpc) Test_ProjectDeleteCmd() {
	s.MockOrgs.SetResponse(&pb.Project{ID: "201", OrgID: "100", Alias: "payments", Name: "Payments", Status: pb.ItemStatus_Inactive})
	a := command.ProjectDeleteCmd{Project: "201"}
	s.runPrinted(func() error { return a.Run(s.Ctl) })
}

func (s *testSuiteGrpc) Test_ProjectListCmd() {
	s.MockOrgs.SetResponse(&pb.ProjectsResponse{Projects: []*pb.Project{testProject}})
	a := command.ProjectListCmd{}
	s.runPrinted(func() error { return a.Run(s.Ctl) })

	a = command.ProjectListCmd{Status: "bogus"}
	err := a.Run(s.Ctl)
	s.EqualError(err, "invalid status: bogus")
}

func (s *testSuiteGrpc) Test_ProjectGetCmd() {
	s.MockOrgs.SetResponse(testProject)
	a := command.ProjectGetCmd{Alias: "payments"}
	s.runPrinted(func() error { return a.Run(s.Ctl) })

	a = command.ProjectGetCmd{}
	err := a.Run(s.Ctl)
	s.EqualError(err, "project ID or alias is required")
}

func (s *testSuiteGrpc) Test_ProjectMembersListCmd() {
	s.MockOrgs.SetResponse(&pb.MembersResponse{
		Memberships: []*pb.Membership{
			{
				ID:           "1",
				OrgID:        "100",
				ProjectID:    "201",
				ProjectAlias: "payments",
				Scope:        pb.Scope_Project,
				Name:         "Test Member",
				Email:        "test@example.com",
				Role:         pb.Role_Admin,
			},
		},
		Invites: []*pb.Invite{
			{
				ID:        "2",
				OrgID:     "100",
				ProjectID: "201",
				Scope:     pb.Scope_Project,
				Email:     "invitee@example.com",
				Role:      pb.Role_User,
			},
		},
	})
	a := command.ProjectMembersListCmd{Project: "201"}
	s.runPrinted(func() error { return a.Run(s.Ctl) })
}

func (s *testSuiteGrpc) Test_ProjectMemberAddCmd() {
	s.MockOrgs.SetResponse(&pb.AddMemberResponse{
		Membership: &pb.Membership{
			ID:        "1",
			OrgID:     "100",
			ProjectID: "201",
			Scope:     pb.Scope_Project,
			Email:     "test@example.com",
			Role:      pb.Role_Admin,
		},
	})
	a := command.ProjectMemberAddCmd{Project: "201", Email: "test@example.com", Role: "Admin"}
	s.runPrinted(func() error { return a.Run(s.Ctl) })

	a = command.ProjectMemberAddCmd{Project: "201", Email: "test@example.com"}
	err := a.Run(s.Ctl)
	s.EqualError(err, "role is required")
}

func (s *testSuiteGrpc) Test_ProjectMemberDeleteCmd() {
	s.MockOrgs.SetResponse(&emptypb.Empty{})
	a := command.ProjectMemberDeleteCmd{Project: "201", User: "7"}
	s.runPrinted(func() error { return a.Run(s.Ctl) })
}

func (s *testSuiteGrpc) Test_ProjectMemberChangeRoleCmd() {
	s.MockOrgs.SetResponse(&pb.Membership{
		ID:        "1",
		OrgID:     "100",
		ProjectID: "201",
		Scope:     pb.Scope_Project,
		Email:     "test@example.com",
		Role:      pb.Role_User,
	})
	a := command.ProjectMemberChangeRoleCmd{Project: "201", User: "7", Role: "User"}
	s.runPrinted(func() error { return a.Run(s.Ctl) })

	a = command.ProjectMemberChangeRoleCmd{Project: "201", User: "7"}
	err := a.Run(s.Ctl)
	s.EqualError(err, "role is required")
}

func (s *testSuiteGrpc) Test_ProjectInviteDeleteCmd() {
	s.MockOrgs.SetResponse(&emptypb.Empty{})
	a := command.ProjectInviteDeleteCmd{Project: "201", Email: "invitee@example.com"}
	s.runPrinted(func() error { return a.Run(s.Ctl) })
}
