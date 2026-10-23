package command

import (
	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
)

// The commands of this file read the Certificate Information Service, the
// read-only view of the CA for authenticated users: they need a login, and
// every lookup names a certificate or an issuer, since the CIS lists
// nothing of an org but its trust anchors.

// CertCmd is the base command of the certificate information
type CertCmd struct {
	Get    CertGetCmd    `cmd:"" help:"get a certificate by ID, key identifier, thumbprint or issuer and serial"`
	Status CertStatusCmd `cmd:"" help:"get the revocation status of a certificate"`
}

// CertSelector names a certificate by its ID, subject key identifier,
// thumbprint, or issuer key identifier and serial number
type CertSelector struct {
	ID     string `arg:"" optional:"" help:"the ID of the certificate"`
	SKID   string `name:"skid" help:"the subject key identifier: the newest certificate of the key"`
	Sha256 string `help:"the SHA-256 thumbprint of the certificate"`
	IKID   string `name:"ikid" help:"the key identifier of the issuer, with --serial"`
	Serial string `help:"the serial number of the certificate, with --ikid"`
}

// request returns the selector as the API carries it
func (s *CertSelector) request() (*pb.GetCertificateInfoRequest, error) {
	if (s.IKID == "") != (s.Serial == "") {
		return nil, errors.New("--ikid and --serial are used together")
	}
	if s.ID == "" && s.SKID == "" && s.Sha256 == "" && s.IKID == "" {
		return nil, errors.New("certificate ID, --skid, --sha256 or --ikid with --serial is required")
	}
	req := &pb.GetCertificateInfoRequest{
		ID:     s.ID,
		SKID:   s.SKID,
		Sha256: s.Sha256,
	}
	if s.IKID != "" {
		req.IssuerSerial = &pb.IssuerSerial{
			IKID:         s.IKID,
			SerialNumber: s.Serial,
		}
	}
	return req, nil
}

// CertGetCmd returns a certificate
type CertGetCmd struct {
	CertSelector `embed:""`
}

// Run the command
func (a *CertGetCmd) Run(app App) error {
	req, err := a.request()
	if err != nil {
		return err
	}
	client, err := app.CISClient()
	if err != nil {
		return err
	}
	res, err := client.GetCertificate(app.Context(), req)
	if err != nil {
		return err
	}
	return app.Print(res)
}

// CertStatusCmd returns the revocation status of a certificate
type CertStatusCmd struct {
	CertSelector `embed:""`
}

// Run the command
func (a *CertStatusCmd) Run(app App) error {
	req, err := a.request()
	if err != nil {
		return err
	}
	client, err := app.CISClient()
	if err != nil {
		return err
	}
	res, err := client.GetCertificateStatus(app.Context(), req)
	if err != nil {
		return err
	}
	return app.Print(res)
}

// IssuerCmd is the base command of the issuer information
type IssuerCmd struct {
	Get IssuerGetCmd `cmd:"" help:"get the certificate chain and URLs of an issuer by key identifier"`
}

// IssuerGetCmd returns an issuer by its key identifier
type IssuerGetCmd struct {
	IKID string `arg:"" help:"the key identifier of the issuer"`
}

// Run the command
func (a *IssuerGetCmd) Run(app App) error {
	client, err := app.CISClient()
	if err != nil {
		return err
	}
	res, err := client.GetIssuer(app.Context(), &pb.GetIssuerInfoRequest{
		IKID: a.IKID,
	})
	if err != nil {
		return err
	}
	return app.Print(res)
}

// CrlCmd is the base command of the CRL information
type CrlCmd struct {
	Get CrlGetCmd `cmd:"" help:"get the current CRL of an issuer by key identifier"`
}

// CrlGetCmd returns the current CRL of an issuer
type CrlGetCmd struct {
	IKID string `arg:"" help:"the key identifier of the issuer"`
}

// Run the command
func (a *CrlGetCmd) Run(app App) error {
	client, err := app.CISClient()
	if err != nil {
		return err
	}
	res, err := client.GetCRL(app.Context(), &pb.GetCrlRequest{
		IKID: a.IKID,
	})
	if err != nil {
		return err
	}
	return app.Print(res)
}

// RootCmd is the base command of the trust anchors
type RootCmd struct {
	List RootListCmd `cmd:"" help:"list the trust anchors of the platform, or of an org"`
}

// RootListCmd lists trust anchors
type RootListCmd struct {
	Org    string `help:"the ID of the org; empty lists the platform anchors"`
	Limit  uint32 `help:"the maximum number of records to return"`
	Offset uint32 `help:"the offset for the offset-based pagination"`
	Cursor string `help:"the cursor for the cursor-based pagination: initial, or the one of the previous page"`
}

// Run the command
func (a *RootListCmd) Run(app App) error {
	client, err := app.CISClient()
	if err != nil {
		return err
	}
	res, err := client.GetRoots(app.Context(), &pb.GetRootsRequest{
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
