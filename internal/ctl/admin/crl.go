package admin

import (
	"github.com/effective-security/trustyca/privpb"
)

// CrlCmd is the base command of the CRLs
type CrlCmd struct {
	Get     CrlGetCmd     `cmd:"" help:"get the current CRL of an issuer"`
	Publish CrlPublishCmd `cmd:"" help:"publish the CRL of an issuer, or the due CRLs of the issuers in scope"`
}

// CrlGetCmd returns the current CRL of an issuer
type CrlGetCmd struct {
	Org  string `help:"the ID of the org; empty finds the CRL of any org"`
	IKID string `name:"ikid" required:"" help:"the key identifier of the issuer"`
}

// Run the command
func (a *CrlGetCmd) Run(app App) error {
	client, err := app.BackendClient()
	if err != nil {
		return err
	}
	res, err := client.GetCRL(app.Context(), &privpb.GetCrlRequest{
		OrgID: a.Org,
		IKID:  a.IKID,
	})
	if err != nil {
		return err
	}
	return app.Print(res)
}

// CrlPublishCmd publishes CRLs on demand: the CRL of one issuer, or the due
// CRLs of the issuers of the org, of its project, or of every org and the
// platform when no org is named
type CrlPublishCmd struct {
	Org     string `help:"the ID of the org; empty publishes for every org and the platform"`
	Project string `help:"the ID of the project, with --org"`
	IKID    string `name:"ikid" help:"the key identifier of the issuer; empty publishes the due CRLs of every issuer in scope"`
	Force   bool   `help:"publish although the current CRL is not due for renewal"`
}

// Run the command
func (a *CrlPublishCmd) Run(app App) error {
	client, err := app.BackendClient()
	if err != nil {
		return err
	}
	res, err := client.PublishCrls(app.Context(), &privpb.PublishCrlsRequest{
		OrgID:     a.Org,
		ProjectID: a.Project,
		IKID:      a.IKID,
		Force:     a.Force,
	})
	if err != nil {
		return err
	}
	return app.Print(res)
}
