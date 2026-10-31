package admin

import (
	"github.com/effective-security/trustyca/privpb"
)

// SummaryCmd returns the counts of the dashboard of an org, or of one of
// its projects: the issuers by status, the certificates by status and by
// expiry, and the issuers that publish CRLs by the state of their CRL
type SummaryCmd struct {
	OrgScope `embed:""`
}

// Run the command
func (a *SummaryCmd) Run(app App) error {
	client, err := app.BackendClient()
	if err != nil {
		return err
	}
	res, err := client.GetSummary(app.Context(), &privpb.GetSummaryRequest{
		OrgID:     a.Org,
		ProjectID: a.Project,
	})
	if err != nil {
		return err
	}
	return app.Print(res)
}
