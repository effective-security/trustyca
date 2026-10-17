package admin

import (
	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/privpb"
)

// ProjectCmd is the base command for project operations
type ProjectCmd struct {
	List ProjectListCmd `cmd:""  help:"list projects"`
	//Member ProjectMemberCmd `cmd:""  help:"members and invites of a project"`
}

type ProjectListCmd struct {
	Status string `help:"the status to filter by"`
	Org    string `help:"the org ID to filter by"`
	Limit  uint32 `help:"the maximum number of records to return"`
	Offset uint32 `help:"the offset for the offset-based pagination"`
}

// Run the command
func (a *ProjectListCmd) Run(app App) error {
	client, err := app.AdminClient()
	if err != nil {
		return err
	}

	req := &privpb.ListProjectsRequest{
		OrgID:  a.Org,
		Limit:  a.Limit,
		Offset: a.Offset,
	}
	if a.Status != "" {
		req.Status = pb.ItemStatus_Unknown.Parse(a.Status)
		if req.Status == pb.ItemStatus_Unknown {
			return errors.New("invalid status")
		}
	}

	res, err := client.ListProjects(app.Context(), req)
	if err != nil {
		return err
	}
	return app.Print(res)
}
