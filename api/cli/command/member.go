package command

import (
	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
)

// MemberCmd is the base command for member operations
type MemberCmd struct {
	List         MembersListCmd      `cmd:""  help:"List members of the org"`
	Add          MemberAddCmd        `cmd:""  help:"Add a new member to the org"`
	Delete       MemberDeleteCmd     `cmd:""  help:"Delete a member from the org"`
	Change       MemberChangeRoleCmd `cmd:""  help:"Change the role of a member"`
	DeleteInvide InviteDeleteCmd     `cmd:""  help:"Delete a member invite from the org"`
}

type MembersListCmd struct {
	Org string `kong:"arg" help:"The ID of the org"`
}

func (a *MembersListCmd) Run(app App) error {
	client, err := app.OrgsClient()
	if err != nil {
		return err
	}
	req := &pb.GetMembersRequest{
		OrgID: a.Org,
	}
	res, err := client.GetMembers(app.Context(), req)
	if err != nil {
		return err
	}
	return app.Print(res)
}

type MemberDeleteCmd struct {
	Org  string `kong:"arg" help:"The ID of the org"`
	User string `kong:"arg" help:"The ID of the user"`
}

func (a *MemberDeleteCmd) Run(app App) error {
	client, err := app.OrgsClient()
	if err != nil {
		return err
	}
	req := &pb.DeleteMemberRequest{
		OrgID:  a.Org,
		UserID: a.User,
	}
	res, err := client.DeleteMember(app.Context(), req)
	if err != nil {
		return err
	}
	return app.Print(res)
}

type InviteDeleteCmd struct {
	Org   string `kong:"arg" help:"The ID of the org"`
	Email string `kong:"arg" help:"The email of the member"`
}

func (a *InviteDeleteCmd) Run(app App) error {
	client, err := app.OrgsClient()
	if err != nil {
		return err
	}
	req := &pb.DeleteInviteRequest{
		OrgID: a.Org,
		Email: a.Email,
	}
	res, err := client.DeleteInvite(app.Context(), req)
	if err != nil {
		return err
	}
	return app.Print(res)
}

type MemberAddCmd struct {
	Org   string `kong:"arg" help:"The ID of the org"`
	Email string `kong:"arg" help:"The email of the member"`
	Role  string `kong:"arg" help:"The role of the member"`
}

func (a *MemberAddCmd) Run(app App) error {
	client, err := app.OrgsClient()
	if err != nil {
		return err
	}
	req := &pb.AddMemberRequest{
		OrgID: a.Org,
		Email: a.Email,
		Role:  pb.Role_Enum_Value[a.Role],
	}
	if req.Role == pb.Role_None {
		return errors.Errorf("role is required")
	}

	res, err := client.AddMember(app.Context(), req)
	if err != nil {
		return err
	}
	return app.Print(res)
}

type MemberChangeRoleCmd struct {
	Org  string `kong:"arg" help:"The ID of the org"`
	User string `kong:"arg" help:"The ID of the user"`
	Role string `kong:"arg" help:"The role of the member"`
}

func (a *MemberChangeRoleCmd) Run(app App) error {
	client, err := app.OrgsClient()
	if err != nil {
		return err
	}
	req := &pb.ChangeMemberRoleRequest{
		OrgID:  a.Org,
		UserID: a.User,
		Role:   pb.Role_Enum_Value[a.Role],
	}
	if req.Role == pb.Role_None {
		return errors.Errorf("role is required")
	}
	res, err := client.ChangeMemberRole(app.Context(), req)
	if err != nil {
		return err
	}
	return app.Print(res)
}
