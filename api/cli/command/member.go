package command

import (
	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
)

// MemberCmd is the base command for org-wide grants in the selected org.
// Project grants are managed with `project member` commands.
type MemberCmd struct {
	List         MembersListCmd      `cmd:""  help:"List members of the selected org"`
	Add          MemberAddCmd        `cmd:""  help:"Grant an org-wide role"`
	Delete       MemberDeleteCmd     `cmd:""  help:"Remove an org-wide grant"`
	Change       MemberChangeRoleCmd `cmd:""  help:"Change the org-wide role of a member"`
	DeleteInvite InviteDeleteCmd     `cmd:""  help:"Delete an org-wide invite"`
}

// MembersListCmd lists members of the selected org
type MembersListCmd struct {
	// All lists grants of all scopes, including project grants
	All bool `help:"list org-wide and project grants; by default only org-wide"`
}

// Run the command
func (a *MembersListCmd) Run(app App) error {
	client, err := app.OrgsClient()
	if err != nil {
		return err
	}
	req := &pb.GetMembersRequest{}
	if !a.All {
		req.Scope = pb.Scope_Org
	}
	res, err := client.GetMembers(app.Context(), req)
	if err != nil {
		return err
	}
	return app.Print(res)
}

// MemberDeleteCmd removes an org-wide grant
type MemberDeleteCmd struct {
	User string `kong:"arg" help:"The ID of the user"`
}

// Run the command
func (a *MemberDeleteCmd) Run(app App) error {
	client, err := app.OrgsClient()
	if err != nil {
		return err
	}
	res, err := client.DeleteMember(app.Context(), &pb.DeleteMemberRequest{
		UserID: a.User,
	})
	if err != nil {
		return err
	}
	return app.Print(res)
}

// InviteDeleteCmd deletes an org-wide invite
type InviteDeleteCmd struct {
	Email string `kong:"arg" help:"The email of the invitee"`
}

// Run the command
func (a *InviteDeleteCmd) Run(app App) error {
	client, err := app.OrgsClient()
	if err != nil {
		return err
	}
	res, err := client.DeleteInvite(app.Context(), &pb.DeleteInviteRequest{
		Email: a.Email,
	})
	if err != nil {
		return err
	}
	return app.Print(res)
}

// MemberAddCmd grants an org-wide role
type MemberAddCmd struct {
	Email string `kong:"arg" help:"The email of the member"`
	Role  string `kong:"arg" help:"The org-wide role: Viewer|User|Support|Billing|Security|Admin|Owner"`
}

// Run the command
func (a *MemberAddCmd) Run(app App) error {
	client, err := app.OrgsClient()
	if err != nil {
		return err
	}
	req := &pb.AddMemberRequest{
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

// MemberChangeRoleCmd changes the org-wide role of a member
type MemberChangeRoleCmd struct {
	User string `kong:"arg" help:"The ID of the user"`
	Role string `kong:"arg" help:"The org-wide role"`
}

// Run the command
func (a *MemberChangeRoleCmd) Run(app App) error {
	client, err := app.OrgsClient()
	if err != nil {
		return err
	}
	req := &pb.ChangeMemberRoleRequest{
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
