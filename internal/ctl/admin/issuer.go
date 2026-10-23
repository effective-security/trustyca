package admin

import (
	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/privpb"
)

// IssuerCmd is the base command of the issuers
type IssuerCmd struct {
	List     IssuerListCmd     `cmd:"" help:"list the issuers of every org, of the platform or of an org"`
	Get      IssuerGetCmd      `cmd:"" help:"get an issuer of an org by ID, label or key identifier"`
	Register IssuerRegisterCmd `cmd:"" help:"create an issuer: a self-signed root, one signed by a parent, or a pending one with a CSR"`
	Import   IssuerImportCmd   `cmd:"" help:"import an issuer from its certificate and key"`
	Activate IssuerActivateCmd `cmd:"" help:"activate a pending issuer with its externally signed certificate"`
	Archive  IssuerArchiveCmd  `cmd:"" help:"archive an active issuer: it signs nothing new but still serves CRL and OCSP"`
	Destroy  IssuerDestroyCmd  `cmd:"" help:"destroy the key of an archived issuer"`
}

// IssuerListCmd lists issuers across orgs, the support view of
// privpb.Admin
type IssuerListCmd struct {
	Org       string `help:"the ID of the org; empty lists every org and the platform"`
	Project   string `help:"the ID of the project, with --org"`
	Platform  bool   `help:"the platform issuers only"`
	Label     string `help:"the label to filter by"`
	Status    string `help:"the status to filter by: Pending|Active|Archived|Destroyed"`
	Type      string `help:"the type to filter by: Root|Intermediate|Issuing|Shaken|ShakenDelegated"`
	PageFlags `embed:""`
}

// Run the command
func (a *IssuerListCmd) Run(app App) error {
	status, err := parseIssuerStatus(a.Status)
	if err != nil {
		return err
	}
	typ, err := parseAuthorityType(a.Type)
	if err != nil {
		return err
	}
	client, err := app.AdminClient()
	if err != nil {
		return err
	}
	res, err := client.ListIssuers(app.Context(), &privpb.ListAllIssuersRequest{
		OrgID:     a.Org,
		ProjectID: a.Project,
		Platform:  a.Platform,
		Label:     a.Label,
		Status:    status,
		Type:      typ,
		Limit:     a.Limit,
		Offset:    a.Offset,
		Cursor:    a.Cursor,
	})
	if err != nil {
		return err
	}
	return app.Print(res)
}

// IssuerGetCmd returns an issuer of an org
type IssuerGetCmd struct {
	OrgScope `embed:""`
	ID       string `arg:"" optional:"" help:"the ID of the issuer"`
	Label    string `help:"the label of the issuer, resolved in the project then in the org"`
	IKID     string `help:"the key identifier of the issuer"`
}

// Run the command
func (a *IssuerGetCmd) Run(app App) error {
	if a.ID == "" && a.Label == "" && a.IKID == "" {
		return errors.New("issuer ID, label or key identifier is required")
	}
	client, err := app.BackendClient()
	if err != nil {
		return err
	}
	res, err := client.GetIssuer(app.Context(), &privpb.GetIssuerRequest{
		OrgID:     a.Org,
		ProjectID: a.Project,
		ID:        a.ID,
		Label:     a.Label,
		IKID:      a.IKID,
	})
	if err != nil {
		return err
	}
	return app.Print(res)
}

// IssuerRegisterCmd creates an issuer of an org: a self-signed root with a
// CA profile of the org, an issuer signed by a parent (an issuer of the org,
// or a platform issuer that allows the profile), or, without a parent, a
// pending issuer whose CSR is signed outside and activated
type IssuerRegisterCmd struct {
	OrgScope       `embed:""`
	Label          string `required:"" help:"the label of the issuer, unique in the org and project"`
	Type           string `required:"" help:"the type: Root|Intermediate|Issuing|Shaken|ShakenDelegated"`
	SubjectFlags   `embed:""`
	SAN            []string `name:"san" help:"the subject alternative names of the issuer certificate"`
	KeyFlags       `embed:""`
	Parent         string `help:"the ID of the signing issuer; empty for a root, or for a pending issuer with a CSR"`
	Profile        string `help:"the CA profile the parent signs with, or a root signs itself with"`
	IssuerSettings `embed:""`
}

// Run the command
func (a *IssuerRegisterCmd) Run(app App) error {
	typ, err := parseAuthorityType(a.Type)
	if err != nil {
		return err
	}
	if typ == pb.AuthorityType_Unknown {
		return errors.New("type is required")
	}
	subject := a.Subject()
	if subject == nil {
		return errors.New("subject is required: --cn")
	}
	client, err := app.BackendClient()
	if err != nil {
		return err
	}
	res, err := client.RegisterIssuer(app.Context(), &privpb.RegisterIssuerRequest{
		OrgID:       a.Org,
		ProjectID:   a.Project,
		Label:       a.Label,
		Type:        typ,
		Subject:     subject,
		KeySpec:     a.Spec(),
		KeyProvider: a.KeyProvider,
		ParentID:    a.Parent,
		Profile:     a.Profile,
		Config:      a.Config(),
		SAN:         a.SAN,
	})
	if err != nil {
		return err
	}
	return app.Print(res)
}

// IssuerImportCmd registers an issuer of an org from an existing
// certificate and its key: a key of a crypto provider by its URI, or a PEM
// key that the service stores wrapped
type IssuerImportCmd struct {
	OrgScope       `embed:""`
	Label          string `required:"" help:"the label of the issuer, unique in the org and project"`
	Type           string `required:"" help:"the type: Root|Intermediate|Issuing|Shaken|ShakenDelegated"`
	Certificate    string `required:"" help:"the PEM file of the issuer certificate"`
	Intermediates  string `help:"the PEM file of the intermediate CA certificates"`
	Root           string `help:"the PEM file of the root CA certificate"`
	KeyURI         string `name:"key-uri" help:"the URI of the key in a crypto provider, e.g. pkcs11:..."`
	KeyFile        string `help:"the PEM file of the private key, stored protected by the service"`
	IssuerSettings `embed:""`
}

// Run the command
func (a *IssuerImportCmd) Run(app App) error {
	typ, err := parseAuthorityType(a.Type)
	if err != nil {
		return err
	}
	if typ == pb.AuthorityType_Unknown {
		return errors.New("type is required")
	}
	if (a.KeyURI == "") == (a.KeyFile == "") {
		return errors.New("one of --key-uri and --key-file is required")
	}
	cert, err := readPEM(a.Certificate, "certificate")
	if err != nil {
		return err
	}
	intermediates, err := readPEM(a.Intermediates, "intermediates")
	if err != nil {
		return err
	}
	root, err := readPEM(a.Root, "root")
	if err != nil {
		return err
	}
	key, err := readPEM(a.KeyFile, "key")
	if err != nil {
		return err
	}
	client, err := app.BackendClient()
	if err != nil {
		return err
	}
	res, err := client.ImportIssuer(app.Context(), &privpb.ImportIssuerRequest{
		OrgID:         a.Org,
		ProjectID:     a.Project,
		Label:         a.Label,
		Type:          typ,
		Certificate:   cert,
		Intermediates: intermediates,
		Root:          root,
		KeyURI:        a.KeyURI,
		KeyPem:        key,
		Config:        a.Config(),
	})
	if err != nil {
		return err
	}
	return app.Print(res)
}

// IssuerActivateCmd sets the externally signed certificate of a pending
// issuer and activates it
type IssuerActivateCmd struct {
	Org           string `required:"" help:"the ID of the org"`
	ID            string `arg:"" help:"the ID of the pending issuer"`
	Certificate   string `required:"" help:"the PEM file of the signed issuer certificate"`
	Intermediates string `help:"the PEM file of the intermediate CA certificates"`
	Root          string `help:"the PEM file of the root CA certificate"`
}

// Run the command
func (a *IssuerActivateCmd) Run(app App) error {
	cert, err := readPEM(a.Certificate, "certificate")
	if err != nil {
		return err
	}
	intermediates, err := readPEM(a.Intermediates, "intermediates")
	if err != nil {
		return err
	}
	root, err := readPEM(a.Root, "root")
	if err != nil {
		return err
	}
	client, err := app.BackendClient()
	if err != nil {
		return err
	}
	res, err := client.ActivateIssuer(app.Context(), &privpb.ActivateIssuerRequest{
		OrgID:         a.Org,
		ID:            a.ID,
		Certificate:   cert,
		Intermediates: intermediates,
		Root:          root,
	})
	if err != nil {
		return err
	}
	return app.Print(res)
}

// IssuerArchiveCmd archives an active issuer
type IssuerArchiveCmd struct {
	Org string `required:"" help:"the ID of the org"`
	ID  string `arg:"" help:"the ID of the issuer"`
}

// Run the command
func (a *IssuerArchiveCmd) Run(app App) error {
	return updateIssuerStatus(app, a.Org, a.ID, pb.IssuerStatus_Archived)
}

// IssuerDestroyCmd destroys the key of an archived issuer; its CRL and OCSP
// are no longer produced
type IssuerDestroyCmd struct {
	Org string `required:"" help:"the ID of the org"`
	ID  string `arg:"" help:"the ID of the issuer"`
}

// Run the command
func (a *IssuerDestroyCmd) Run(app App) error {
	return updateIssuerStatus(app, a.Org, a.ID, pb.IssuerStatus_Destroyed)
}

// updateIssuerStatus moves an issuer of the org to the status and prints it
func updateIssuerStatus(app App, orgID, id string, status pb.IssuerStatus_Enum) error {
	client, err := app.BackendClient()
	if err != nil {
		return err
	}
	res, err := client.UpdateIssuer(app.Context(), &privpb.UpdateIssuerRequest{
		OrgID:  orgID,
		ID:     id,
		Status: status,
	})
	if err != nil {
		return err
	}
	return app.Print(res)
}
