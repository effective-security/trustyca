package command

import (
	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
)

// ProjectCmd is the base command for project operations in the selected org
type ProjectCmd struct {
	Create ProjectCreateCmd `cmd:"" help:"create a new project"`
	Update ProjectUpdateCmd `cmd:"" help:"update a project"`
	Delete ProjectDeleteCmd `cmd:"" help:"delete a project"`
	List   ProjectListCmd   `cmd:"" help:"list accessible projects"`
	Get    ProjectGetCmd    `cmd:"" help:"get a project by ID or alias"`
	Member ProjectMemberCmd `cmd:"" help:"project grant commands"`
}

// ProjectCreateCmd creates a project
type ProjectCreateCmd struct {
	Name        string `kong:"arg" help:"the name of the project"`
	Alias       string `help:"the org-unique alias of the project, e.g. a cloud account ID; generated when empty"`
	Description string `help:"the description of the project"`
}

// Run the command
func (a *ProjectCreateCmd) Run(app App) error {
	client, err := app.OrgsClient()
	if err != nil {
		return err
	}
	res, err := client.RegisterProject(app.Context(), &pb.RegisterProjectRequest{
		Alias:       a.Alias,
		Name:        a.Name,
		Description: a.Description,
	})
	if err != nil {
		return err
	}
	return app.Print(res)
}

// ProjectUpdateCmd updates a project
type ProjectUpdateCmd struct {
	Project     string `kong:"arg" help:"the ID of the project"`
	Name        string `help:"the name of the project"`
	Description string `help:"the description of the project"`
}

// Run the command
func (a *ProjectUpdateCmd) Run(app App) error {
	client, err := app.OrgsClient()
	if err != nil {
		return err
	}
	res, err := client.UpdateProject(app.Context(), &pb.UpdateProjectRequest{
		ProjectID:   a.Project,
		Name:        a.Name,
		Description: a.Description,
	})
	if err != nil {
		return err
	}
	return app.Print(res)
}

// ProjectDeleteCmd deletes a project
type ProjectDeleteCmd struct {
	Project string `kong:"arg" help:"the ID of the project"`
}

// Run the command
func (a *ProjectDeleteCmd) Run(app App) error {
	client, err := app.OrgsClient()
	if err != nil {
		return err
	}
	res, err := client.DeleteProject(app.Context(), &pb.DeleteProjectRequest{
		ProjectID: a.Project,
	})
	if err != nil {
		return err
	}
	return app.Print(res)
}

// ProjectListCmd lists accessible projects
type ProjectListCmd struct {
	Status string `help:"the status to filter by"`
	Limit  uint32 `help:"maximum number of records to return"`
	Offset uint32 `help:"offset for pagination"`
}

// Run the command
func (a *ProjectListCmd) Run(app App) error {
	client, err := app.OrgsClient()
	if err != nil {
		return err
	}
	req := &pb.ListProjectsRequest{
		Limit:  a.Limit,
		Offset: a.Offset,
	}
	if a.Status != "" {
		req.Status = pb.ItemStatus_Unknown.Parse(a.Status)
		if req.Status == pb.ItemStatus_Unknown {
			return errors.Errorf("invalid status: %s", a.Status)
		}
	}
	res, err := client.ListProjects(app.Context(), req)
	if err != nil {
		return err
	}
	return app.Print(res)
}

// ProjectGetCmd returns a project
type ProjectGetCmd struct {
	Project string `kong:"arg" optional:"" help:"the ID of the project"`
	Alias   string `help:"the alias of the project, if the ID is not provided"`
}

// Run the command
func (a *ProjectGetCmd) Run(app App) error {
	if a.Project == "" && a.Alias == "" {
		return errors.New("project ID or alias is required")
	}
	client, err := app.OrgsClient()
	if err != nil {
		return err
	}
	res, err := client.GetProject(app.Context(), &pb.GetProjectRequest{
		ProjectID: a.Project,
		Alias:     a.Alias,
	})
	if err != nil {
		return err
	}
	return app.Print(res)
}

// ProjectMemberCmd is the base command for project grants
type ProjectMemberCmd struct {
	List         ProjectMembersListCmd      `cmd:"" help:"list project grants and invites"`
	Add          ProjectMemberAddCmd        `cmd:"" help:"grant a project role"`
	Delete       ProjectMemberDeleteCmd     `cmd:"" help:"remove a project grant"`
	Change       ProjectMemberChangeRoleCmd `cmd:"" help:"change the project role of a member"`
	DeleteInvite ProjectInviteDeleteCmd     `cmd:"" help:"delete a project invite"`
}

// ProjectMembersListCmd lists project grants
type ProjectMembersListCmd struct {
	Project string `kong:"arg" help:"the ID of the project"`
}

// Run the command
func (a *ProjectMembersListCmd) Run(app App) error {
	client, err := app.OrgsClient()
	if err != nil {
		return err
	}
	res, err := client.GetMembers(app.Context(), &pb.GetMembersRequest{
		ProjectID: a.Project,
	})
	if err != nil {
		return err
	}
	return app.Print(res)
}

// ProjectMemberAddCmd grants a project role
type ProjectMemberAddCmd struct {
	Project string `kong:"arg" help:"the ID of the project"`
	Email   string `kong:"arg" help:"the email of the member"`
	Role    string `kong:"arg" help:"the project role: Viewer|User|Support|Security|Admin"`
}

// Run the command
func (a *ProjectMemberAddCmd) Run(app App) error {
	client, err := app.OrgsClient()
	if err != nil {
		return err
	}
	req := &pb.AddMemberRequest{
		ProjectID: a.Project,
		Email:     a.Email,
		Role:      pb.Role_Enum_Value[a.Role],
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

// ProjectMemberDeleteCmd removes a project grant
type ProjectMemberDeleteCmd struct {
	Project string `kong:"arg" help:"the ID of the project"`
	User    string `kong:"arg" help:"the ID of the user"`
}

// Run the command
func (a *ProjectMemberDeleteCmd) Run(app App) error {
	client, err := app.OrgsClient()
	if err != nil {
		return err
	}
	res, err := client.DeleteMember(app.Context(), &pb.DeleteMemberRequest{
		ProjectID: a.Project,
		UserID:    a.User,
	})
	if err != nil {
		return err
	}
	return app.Print(res)
}

// ProjectMemberChangeRoleCmd changes the project role of a member
type ProjectMemberChangeRoleCmd struct {
	Project string `kong:"arg" help:"the ID of the project"`
	User    string `kong:"arg" help:"the ID of the user"`
	Role    string `kong:"arg" help:"the project role"`
}

// Run the command
func (a *ProjectMemberChangeRoleCmd) Run(app App) error {
	client, err := app.OrgsClient()
	if err != nil {
		return err
	}
	req := &pb.ChangeMemberRoleRequest{
		ProjectID: a.Project,
		UserID:    a.User,
		Role:      pb.Role_Enum_Value[a.Role],
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

// ProjectInviteDeleteCmd deletes a project invite
type ProjectInviteDeleteCmd struct {
	Project string `kong:"arg" help:"the ID of the project"`
	Email   string `kong:"arg" help:"the email of the invitee"`
}

// Run the command
func (a *ProjectInviteDeleteCmd) Run(app App) error {
	client, err := app.OrgsClient()
	if err != nil {
		return err
	}
	res, err := client.DeleteInvite(app.Context(), &pb.DeleteInviteRequest{
		ProjectID: a.Project,
		Email:     a.Email,
	})
	if err != nil {
		return err
	}
	return app.Print(res)
}
