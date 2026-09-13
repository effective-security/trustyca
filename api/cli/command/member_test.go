package command_test

import (
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/trustyca/api/cli/command"
	"github.com/effective-security/trustyca/api/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/emptypb"
)

func (s *testSuiteGrpc) Test_MembersListCmd() {
	expectedResponse := &pb.MembersResponse{
		Memberships: []*pb.Membership{
			{
				ID:    "1",
				Name:  "Test Member",
				Email: "test@example.com",
				Role:  pb.Role_Admin,
			},
		},
		Invites: []*pb.Invite{
			{
				ID:    "2",
				Email: "test@example.com",
				Role:  pb.Role_Admin,
			},
		},
	}
	s.MockOrgs.SetResponse(expectedResponse)

	a := command.MembersListCmd{}
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

func (s *testSuiteGrpc) Test_MemberDeleteCmd() {
	expectedResponse := &emptypb.Empty{}
	s.MockOrgs.SetResponse(expectedResponse)

	a := command.MemberDeleteCmd{}
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

func (s *testSuiteGrpc) Test_MemberChangeRoleCmd() {
	expectedResponse := &pb.Membership{
		ID:    "1",
		Name:  "Test Member",
		Email: "test@example.com",
		Role:  pb.Role_Admin,
	}
	s.MockOrgs.SetResponse(expectedResponse)

	a := command.MemberChangeRoleCmd{}
	err := a.Run(s.Ctl)
	s.EqualError(err, "role is required")

	a.Role = "Admin"

	err = a.Run(s.Ctl)
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

func (s *testSuiteGrpc) Test_InviteDeleteCmd() {
	expectedResponse := &emptypb.Empty{}
	s.MockOrgs.SetResponse(expectedResponse)

	a := command.InviteDeleteCmd{}
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

func (s *testSuiteGrpc) Test_MemberAddCmd() {
	expectedResponse := &pb.AddMemberResponse{
		Invite: &pb.Invite{
			ID:    "1",
			Email: "test@example.com",
			Role:  pb.Role_Admin,
		},
	}
	s.MockOrgs.SetResponse(expectedResponse)

	a := command.MemberAddCmd{}
	err := a.Run(s.Ctl)
	s.EqualError(err, "role is required")

	a.Role = "Admin"

	err = a.Run(s.Ctl)
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
