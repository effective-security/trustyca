package command

import (
	"github.com/effective-security/trustyca/api/pb"
	"google.golang.org/protobuf/types/known/emptypb"
)

// OrgCmd is the base command for org operations.
// Commands act on the org selected in the token, see `auth org`.
type OrgCmd struct {
	Create OrgCreateCmd `cmd:""  help:"create a new org"`
	Update OrgUpdateCmd `cmd:""  help:"update the selected org"`
	Delete OrgDeleteCmd `cmd:""  help:"delete the selected org"`
	List   OrgListCmd   `cmd:""  help:"list orgs the user can select"`
	Get    OrgGetCmd    `cmd:""  help:"get the selected org"`
	Access OrgAccessCmd `cmd:""  help:"print the user's access to the selected org"`
}

// OrgCreateCmd creates an org; the caller becomes its Owner
type OrgCreateCmd struct {
	Name        string `kong:"arg" help:"the name of the org"`
	Description string `help:"the description of the org"`
}

// Run the command
func (a *OrgCreateCmd) Run(app App) error {
	client, err := app.OrgsClient()
	if err != nil {
		return err
	}
	res, err := client.RegisterOrg(app.Context(), &pb.RegisterOrgRequest{
		Name:        a.Name,
		Description: a.Description,
	})
	if err != nil {
		return err
	}
	return app.Print(res)
}

// OrgUpdateCmd updates the selected org
type OrgUpdateCmd struct {
	Name        string `required:"" help:"the name of the org"`
	Description string `help:"the description of the org"`
}

// Run the command
func (a *OrgUpdateCmd) Run(app App) error {
	client, err := app.OrgsClient()
	if err != nil {
		return err
	}

	res, err := client.UpdateOrg(app.Context(), &pb.UpdateOrgRequest{
		Name:        a.Name,
		Description: a.Description,
	})
	if err != nil {
		return err
	}
	return app.Print(res)
}

// OrgDeleteCmd deletes the selected org
type OrgDeleteCmd struct {
}

// Run the command
func (a *OrgDeleteCmd) Run(app App) error {
	client, err := app.OrgsClient()
	if err != nil {
		return err
	}

	res, err := client.DeleteOrg(app.Context(), &emptypb.Empty{})
	if err != nil {
		return err
	}
	return app.Print(res)
}

// OrgListCmd lists the orgs the user can select
type OrgListCmd struct {
}

// Run the command
func (a *OrgListCmd) Run(app App) error {
	client, err := app.OrgsClient()
	if err != nil {
		return err
	}

	res, err := client.GetUserOrgs(app.Context(), &emptypb.Empty{})
	if err != nil {
		return err
	}
	return app.Print(res)
}

// OrgGetCmd returns the selected org
type OrgGetCmd struct {
}

// Run the command
func (a *OrgGetCmd) Run(app App) error {
	client, err := app.OrgsClient()
	if err != nil {
		return err
	}
	res, err := client.GetOrg(app.Context(), &emptypb.Empty{})
	if err != nil {
		return err
	}
	return app.Print(res)
}

// OrgAccessCmd prints the user's resolved access and grants in the selected org
type OrgAccessCmd struct {
}

// Run the command
func (a *OrgAccessCmd) Run(app App) error {
	client, err := app.OrgsClient()
	if err != nil {
		return err
	}
	res, err := client.GetUserMemberships(app.Context(), &emptypb.Empty{})
	if err != nil {
		return err
	}
	return app.Print(res)
}
