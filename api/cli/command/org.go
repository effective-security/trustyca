package command

import (
	"github.com/effective-security/trustyca/api/pb"
	"google.golang.org/protobuf/types/known/emptypb"
)

// OrgCmd is the base command for org operations
type OrgCmd struct {
	Create OrgCreateCmd `cmd:""  help:"create a new org"`
	Update OrgUpdateCmd `cmd:""  help:"update a org"`
	Delete OrgDeleteCmd `cmd:""  help:"delete a org"`
	List   OrgListCmd   `cmd:""  help:"list orgs"`
	Get    OrgGetCmd    `cmd:""  help:"get a org"`
}

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

type OrgUpdateCmd struct {
	ID          string `kong:"arg" help:"the ID of the org"`
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
		OrgID:       a.ID,
		Name:        a.Name,
		Description: a.Description,
	})
	if err != nil {
		return err
	}
	return app.Print(res)
}

type OrgDeleteCmd struct {
	ID string `kong:"arg" help:"the ID of the org"`
}

// Run the command
func (a *OrgDeleteCmd) Run(app App) error {
	client, err := app.OrgsClient()
	if err != nil {
		return err
	}

	res, err := client.DeleteOrg(app.Context(), &pb.DeleteOrgRequest{
		OrgID: a.ID,
	})
	if err != nil {
		return err
	}
	return app.Print(res)
}

type OrgListCmd struct {
}

// Run the command
func (a *OrgListCmd) Run(app App) error {
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

type OrgGetCmd struct {
	ID string `kong:"arg" help:"the ID of the org"`
}

// Run the command
func (a *OrgGetCmd) Run(app App) error {
	client, err := app.OrgsClient()
	if err != nil {
		return err
	}
	res, err := client.GetOrg(app.Context(), &pb.GetOrgRequest{
		OrgID: a.ID,
	})
	if err != nil {
		return err
	}
	return app.Print(res)
}
