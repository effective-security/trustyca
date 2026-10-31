package command

import (
	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
)

// EventCmd provides the audit event commands
type EventCmd struct {
	List EventListCmd `cmd:"" help:"list the audit events of the selected org, newest first"`
}

// EventListCmd lists the audit events the caller may see: every event of
// the org with an org-wide role, the org-wide events and those of the
// caller's projects with project grants only, or the events of one project
type EventListCmd struct {
	Project string `help:"the ID of the project to list the events of"`
	Type    string `help:"the event type to filter by"`
	After   string `help:"the inclusive start of the time range, in RFC3339 format"`
	Before  string `help:"the exclusive end of the time range, in RFC3339 format"`
	Limit   uint32 `help:"the maximum number of records to return"`
	Cursor  string `help:"the cursor of the previous page; empty for the first page"`
}

// Run the command
func (a *EventListCmd) Run(app App) error {
	client, err := app.OrgsClient()
	if err != nil {
		return err
	}
	req := &pb.ListEventsRequest{
		ProjectID: a.Project,
		After:     a.After,
		Before:    a.Before,
		Limit:     a.Limit,
		Cursor:    a.Cursor,
	}
	if a.Type != "" {
		if req.Type = pb.EventType_Unknown.Parse(a.Type); req.Type == pb.EventType_Unknown {
			return errors.Errorf("invalid event type: %s", a.Type)
		}
	}
	res, err := client.ListEvents(app.Context(), req)
	if err != nil {
		return err
	}
	return app.Print(res)
}
