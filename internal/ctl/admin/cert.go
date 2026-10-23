package admin

import (
	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/privpb"
)

// CertCmd is the base command of the certificates
type CertCmd struct {
	List   CertListCmd   `cmd:"" help:"list the certificates of every org, of the platform or of an org"`
	Get    CertGetCmd    `cmd:"" help:"get a certificate of an org by ID, key identifier, thumbprint or issuer and serial"`
	Revoke CertRevokeCmd `cmd:"" help:"revoke a certificate of an org"`
}

// CertListCmd lists certificates across orgs, the support view of
// privpb.Admin
type CertListCmd struct {
	Org            string `help:"the ID of the org; empty lists every org and the platform"`
	Project        string `help:"the ID of the project, with --org"`
	Platform       bool   `help:"the platform certificates only"`
	IKID           string `name:"ikid" help:"the key identifier of the issuer to filter by"`
	Profile        string `help:"the profile label to filter by"`
	Status         string `help:"the status to filter by: Active|Expired|Revoked"`
	ExpiringBefore string `help:"the certificates whose validity ends before the RFC3339 time"`
	PageFlags      `embed:""`
}

// Run the command
func (a *CertListCmd) Run(app App) error {
	status, err := parseCertificateStatus(a.Status)
	if err != nil {
		return err
	}
	client, err := app.AdminClient()
	if err != nil {
		return err
	}
	res, err := client.ListCertificates(app.Context(), &privpb.ListAllCertificatesRequest{
		OrgID:          a.Org,
		ProjectID:      a.Project,
		Platform:       a.Platform,
		IKID:           a.IKID,
		Profile:        a.Profile,
		Status:         status,
		ExpiringBefore: a.ExpiringBefore,
		Limit:          a.Limit,
		Offset:         a.Offset,
		Cursor:         a.Cursor,
	})
	if err != nil {
		return err
	}
	return app.Print(res)
}

// CertSelector names a certificate of an org by its ID, subject key
// identifier, thumbprint, or issuer key identifier and serial number
type CertSelector struct {
	ID     string `arg:"" optional:"" help:"the ID of the certificate"`
	SKID   string `name:"skid" help:"the subject key identifier: the newest certificate of the key"`
	Sha256 string `help:"the SHA-256 thumbprint of the certificate"`
	IKID   string `name:"ikid" help:"the key identifier of the issuer, with --serial"`
	Serial string `help:"the serial number of the certificate, with --ikid"`
}

// issuerSerial returns the issuer and serial selector, or nil
func (s *CertSelector) issuerSerial() *pb.IssuerSerial {
	if s.IKID == "" && s.Serial == "" {
		return nil
	}
	return &pb.IssuerSerial{
		IKID:         s.IKID,
		SerialNumber: s.Serial,
	}
}

// validate checks that the selector names a certificate
func (s *CertSelector) validate() error {
	if (s.IKID == "") != (s.Serial == "") {
		return errors.New("--ikid and --serial are used together")
	}
	if s.ID == "" && s.SKID == "" && s.Sha256 == "" && s.IKID == "" {
		return errors.New("certificate ID, --skid, --sha256 or --ikid with --serial is required")
	}
	return nil
}

// CertGetCmd returns a certificate of an org
type CertGetCmd struct {
	Org          string `required:"" help:"the ID of the org"`
	CertSelector `embed:""`
}

// Run the command
func (a *CertGetCmd) Run(app App) error {
	err := a.validate()
	if err != nil {
		return err
	}
	client, err := app.BackendClient()
	if err != nil {
		return err
	}
	res, err := client.GetCertificate(app.Context(), &privpb.GetCertificateRequest{
		OrgID:        a.Org,
		ID:           a.ID,
		SKID:         a.SKID,
		Sha256:       a.Sha256,
		IssuerSerial: a.issuerSerial(),
	})
	if err != nil {
		return err
	}
	return app.Print(res)
}

// CertRevokeCmd revokes a certificate of an org
type CertRevokeCmd struct {
	OrgScope     `embed:""`
	CertSelector `embed:""`
	Reason       string `help:"the reason: Unspecified|KeyCompromise|CACompromise|AffiliationChanged|Superseded|CessationOfOperation|CertificateHold|PrivilegeWithdrawn|AACompromise"`
	ReasonText   string `help:"a note on the revocation"`
}

// Run the command
func (a *CertRevokeCmd) Run(app App) error {
	err := a.validate()
	if err != nil {
		return err
	}
	if a.Sha256 != "" {
		return errors.New("a revocation names the certificate by ID, --skid or --ikid with --serial")
	}
	reason := pb.ReasonCode_Unspecified
	if a.Reason != "" {
		if reason = pb.ReasonCode_Unspecified.Parse(a.Reason); reason == pb.ReasonCode_Unspecified && a.Reason != pb.ReasonCode_Unspecified.String() {
			return errors.Errorf("invalid reason: %s", a.Reason)
		}
	}
	client, err := app.BackendClient()
	if err != nil {
		return err
	}
	res, err := client.RevokeCertificate(app.Context(), &privpb.RevokeCertificateRequest{
		OrgID:        a.Org,
		ProjectID:    a.Project,
		ID:           a.ID,
		SKID:         a.SKID,
		IssuerSerial: a.issuerSerial(),
		Reason:       reason,
		ReasonText:   a.ReasonText,
	})
	if err != nil {
		return err
	}
	return app.Print(res)
}
