package admin

import (
	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/privpb"
)

// RootCmd is the base command of the trust anchors
type RootCmd struct {
	List     RootListCmd     `cmd:"" help:"list the trust anchors of an org, or of the platform"`
	Register RootRegisterCmd `cmd:"" help:"register a self-signed CA certificate as a trust anchor of an org"`
}

// RootListCmd lists trust anchors
type RootListCmd struct {
	Org       string `help:"the ID of the org; empty lists the platform anchors"`
	PageFlags `embed:""`
}

// Run the command
func (a *RootListCmd) Run(app App) error {
	client, err := app.BackendClient()
	if err != nil {
		return err
	}
	res, err := client.ListRoots(app.Context(), &privpb.ListRootsRequest{
		OrgID:  a.Org,
		Limit:  a.Limit,
		Offset: a.Offset,
		Cursor: a.Cursor,
	})
	if err != nil {
		return err
	}
	return app.Print(res)
}

// RootRegisterCmd registers an external trust anchor of an org
type RootRegisterCmd struct {
	Org         string `required:"" help:"the ID of the org"`
	Certificate string `required:"" help:"the PEM file of the self-signed CA certificate"`
	Trust       string `help:"the trust scope: Public|Private; empty for any"`
}

// Run the command
func (a *RootRegisterCmd) Run(app App) error {
	trust := pb.Trust_Any
	if a.Trust != "" {
		if trust = pb.Trust_Any.Parse(a.Trust); trust == pb.Trust_Any {
			return errors.Errorf("invalid trust: %s", a.Trust)
		}
	}
	pem, err := readPEM(a.Certificate, "certificate")
	if err != nil {
		return err
	}
	client, err := app.BackendClient()
	if err != nil {
		return err
	}
	res, err := client.RegisterRoot(app.Context(), &privpb.RegisterRootRequest{
		OrgID: a.Org,
		Pem:   pem,
		Trust: trust,
	})
	if err != nil {
		return err
	}
	return app.Print(res)
}
