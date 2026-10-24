package admin

import (
	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/privpb"
)

// OrgCmd is the base command for project operations
type OrgCmd struct {
	List OrgListCmd `cmd:""  help:"list orgs"`
}

type OrgListCmd struct {
	Status string `help:"the status to filter by"`
	Limit  uint32 `help:"the maximum number of records to return"`
	Offset uint32 `help:"the offset for the offset-based pagination"`
	Cursor string `help:"the cursor for the cursor-based pagination: initial, or the one of the previous page"`
}

// Run the command
func (a *OrgListCmd) Run(app App) error {
	client, err := app.AdminClient()
	if err != nil {
		return err
	}

	req := &privpb.ListOrgsRequest{
		Limit:  a.Limit,
		Offset: a.Offset,
		Cursor: a.Cursor,
	}
	if a.Status != "" {
		req.Status = pb.ItemStatus_Unknown.Parse(a.Status)
		if req.Status == pb.ItemStatus_Unknown {
			return errors.Errorf("invalid status: %s", a.Status)
		}
	}

	res, err := client.ListOrgs(app.Context(), req)
	if err != nil {
		return err
	}
	return app.Print(res)
}
