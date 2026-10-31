package admin

import (
	"os"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/x/fileutil/resolve"
)

// CACmd is the base command of the Certification Authority operations: the
// issuers, profiles, trust anchors, certificates and CRLs of an org through
// pb.CA, the support lists across orgs through privpb.Admin, and the
// onboarding of an org. The CA API is served by the backend listener and
// authorizes the trustyca-admin identity of the client certificate, which
// names the org of every request.
type CACmd struct {
	Issuer  IssuerCmd  `cmd:"" help:"issuer commands"`
	Profile ProfileCmd `cmd:"" help:"certificate profile commands"`
	Root    RootCmd    `cmd:"" help:"trust anchor commands"`
	Cert    CertCmd    `cmd:"" help:"certificate commands"`
	Crl     CrlCmd     `cmd:"" help:"CRL commands"`
	Org     CAOrgCmd   `cmd:"" help:"org onboarding commands"`
	Summary SummaryCmd `cmd:"" help:"the counts of the issuers, certificates and CRLs of an org"`
}

// OrgScope names the org of a CA request, and its project when the rows
// belong to one
type OrgScope struct {
	Org     string `required:"" help:"the ID of the org"`
	Project string `help:"the ID of the project; empty for the org scope"`
}

// PageFlags are the pagination flags of a list
type PageFlags struct {
	Limit  uint32 `help:"the maximum number of records to return"`
	Offset uint32 `help:"the offset for the offset-based pagination"`
	Cursor string `help:"the cursor for the cursor-based pagination: initial, or the one of the previous page"`
}

// IssuerSettings are the runtime settings of an issuer: the URL templates
// of the certificates it issues, the CRL and OCSP timings and the profiles
// it may sign
type IssuerSettings struct {
	AiaURL                 string   `name:"aia-url" help:"the AIA issuer URL template; :ISSUER_ID is replaced with the issuer key identifier"`
	CrlURL                 string   `name:"crl-url" help:"the CRL distribution point URL template, with :ISSUER_ID"`
	OcspURL                string   `name:"ocsp-url" help:"the OCSP URL template, with :ISSUER_ID"`
	CrlExpiry              string   `help:"the validity of a CRL, e.g. 48h"`
	CrlRenewal             string   `help:"how long before its next update a CRL is renewed, e.g. 12h"`
	OcspExpiry             string   `help:"the validity of an OCSP response, e.g. 1h"`
	OcspProfile            string   `help:"the profile of the delegated OCSP responder certificate; empty signs OCSP with the issuer key"`
	AllowedProfiles        []string `help:"the profiles the issuer may sign; required for the profiles bound to any issuer"`
	OmitDisabledExtensions bool     `help:"drop the extensions a profile does not allow instead of failing the request"`
}

// Config returns the settings as the API carries them, or nil when none is
// set
func (f *IssuerSettings) Config() *pb.IssuerConfig {
	if f.AiaURL == "" && f.CrlURL == "" && f.OcspURL == "" &&
		f.CrlExpiry == "" && f.CrlRenewal == "" && f.OcspExpiry == "" &&
		f.OcspProfile == "" && len(f.AllowedProfiles) == 0 && !f.OmitDisabledExtensions {
		return nil
	}
	return &pb.IssuerConfig{
		AiaURL:                 f.AiaURL,
		OcspURL:                f.OcspURL,
		CrlURL:                 f.CrlURL,
		CrlExpiry:              f.CrlExpiry,
		CrlRenewal:             f.CrlRenewal,
		OcspExpiry:             f.OcspExpiry,
		DelegatedOcspProfile:   f.OcspProfile,
		AllowedProfiles:        f.AllowedProfiles,
		OmitDisabledExtensions: f.OmitDisabledExtensions,
	}
}

// SubjectFlags are the subject of an issuer certificate
type SubjectFlags struct {
	CN           string `name:"cn" help:"the common name of the subject"`
	Organization string `help:"the organization of the subject"`
	Unit         string `help:"the organizational unit of the subject"`
	Country      string `help:"the country of the subject"`
	State        string `help:"the state or province of the subject"`
	Locality     string `help:"the locality of the subject"`
}

// Subject returns the subject as the API carries it, or nil when no field
// is set
func (f *SubjectFlags) Subject() *pb.X509Subject {
	if f.CN == "" && f.Organization == "" && f.Unit == "" && f.Country == "" && f.State == "" && f.Locality == "" {
		return nil
	}
	res := &pb.X509Subject{
		CommonName: f.CN,
	}
	if f.Organization != "" || f.Unit != "" || f.Country != "" || f.State != "" || f.Locality != "" {
		res.Names = []*pb.X509Name{{
			Country:            f.Country,
			State:              f.State,
			Locality:           f.Locality,
			Organisation:       f.Organization,
			OrganisationalUnit: f.Unit,
		}}
	}
	return res
}

// KeyFlags select the key of a new issuer
type KeyFlags struct {
	KeyAlgo     string `help:"the key algorithm: ECDSA|RSA; empty for the server default, ECDSA P-256"`
	KeySize     int32  `help:"the RSA key size in bits, or the ECDSA curve size: 256|384|521"`
	KeyProvider string `help:"the crypto provider of the key; empty for the server default"`
}

// Spec returns the key specification as the API carries it, or nil for the
// server default
func (f *KeyFlags) Spec() *pb.KeySpec {
	if f.KeyAlgo == "" && f.KeySize == 0 {
		return nil
	}
	return &pb.KeySpec{
		Algo: f.KeyAlgo,
		Size: f.KeySize,
	}
}

// readPEM returns the content of a PEM file of the operator, with ~ expanded
func readPEM(path, what string) (string, error) {
	if path == "" {
		return "", nil
	}
	data, err := os.ReadFile(resolve.ExpandPath(path))
	if err != nil {
		return "", errors.WithMessagef(err, "unable to read the %s", what)
	}
	return strings.TrimSpace(string(data)), nil
}

// parseIssuerStatus parses an issuer status of a flag; empty is Unknown,
// which filters nothing
func parseIssuerStatus(val string) (pb.IssuerStatus_Enum, error) {
	if val == "" {
		return pb.IssuerStatus_Unknown, nil
	}
	status := pb.IssuerStatus_Unknown.Parse(val)
	if status == pb.IssuerStatus_Unknown {
		return status, errors.Errorf("invalid status: %s", val)
	}
	return status, nil
}

// parseAuthorityType parses an authority type of a flag; empty is Unknown,
// which filters nothing
func parseAuthorityType(val string) (pb.AuthorityType_Enum, error) {
	if val == "" {
		return pb.AuthorityType_Unknown, nil
	}
	typ := pb.AuthorityType_Unknown.Parse(val)
	if typ == pb.AuthorityType_Unknown {
		return typ, errors.Errorf("invalid type: %s", val)
	}
	return typ, nil
}

// parseCertificateStatus parses a certificate status of a flag; empty is
// Unknown, which filters nothing
func parseCertificateStatus(val string) (pb.CertificateStatus_Enum, error) {
	if val == "" {
		return pb.CertificateStatus_Unknown, nil
	}
	status := pb.CertificateStatus_Unknown.Parse(val)
	if status == pb.CertificateStatus_Unknown {
		return status, errors.Errorf("invalid status: %s", val)
	}
	return status, nil
}

// isID tells an ID of the API from a label: IDs are decimal
func isID(val string) bool {
	if val == "" {
		return false
	}
	for _, r := range val {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
