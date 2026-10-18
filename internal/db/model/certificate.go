package model

import (
	"crypto/x509"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xpki/certutil"
)

// NewCertificate builds the issuance record of a signed certificate.
// The caller sets Label, Locations and Metadata; the status defaults to
// Active on registration.
func NewCertificate(crt *x509.Certificate, orgID, projectID xdb.ID, profile, pem, issuersPem, label string, locations []string, metadata xdb.Metadata) *Certificate {
	return &Certificate{
		OrgID:        orgID,
		ProjectID:    projectID,
		Skid:         certutil.GetSubjectKeyID(crt),
		Ikid:         certutil.GetAuthorityKeyID(crt),
		SerialNumber: crt.SerialNumber.String(),
		NotBefore:    xdb.UTC(crt.NotBefore),
		NotAfter:     xdb.UTC(crt.NotAfter),
		Subject:      crt.Subject.String(),
		Issuer:       crt.Issuer.String(),
		Sha256:       certutil.SHA256Hex(crt.Raw),
		Profile:      profile,
		Pem:          pem,
		IssuersPem:   issuersPem,
		Metadata:     metadata,
		Label:        label,
		Locations:    locations,
		Status:       pb.CertificateStatus_Active,
		CreatedAt:    xdb.UTC(time.Now()),
	}
}

// Validate returns error if the model is not valid
func (m *Certificate) Validate() error {
	if err := validateTenancy(m.OrgID, m.ProjectID); err != nil {
		return err
	}
	if err := validateLength("skid", m.Skid, MaxLenForLabel, true); err != nil {
		return err
	}
	if err := validateLength("ikid", m.Ikid, MaxLenForLabel, true); err != nil {
		return err
	}
	if err := validateLength("serial number", m.SerialNumber, MaxLenForLabel, true); err != nil {
		return err
	}
	if err := validateLength("subject", m.Subject, MaxLenForName, true); err != nil {
		return err
	}
	if err := validateLength("issuer", m.Issuer, MaxLenForName, true); err != nil {
		return err
	}
	if len(m.Sha256) != MaxLenForSha256 {
		return errors.New("invalid sha256 length")
	}
	if err := validateLength("profile", m.Profile, MaxLenForLabel, true); err != nil {
		return err
	}
	if err := validateLength("label", m.Label, MaxLenForName, false); err != nil {
		return err
	}
	for _, loc := range m.Locations {
		if err := validateLength("location", loc, MaxLenForName, true); err != nil {
			return err
		}
	}
	if m.NotBefore.IsZero() || m.NotAfter.IsZero() || !m.NotAfter.UTC().After(m.NotBefore.UTC()) {
		return errors.New("invalid validity period")
	}
	if m.Pem == "" {
		return errors.New("invalid pem: required")
	}
	if m.Status == pb.CertificateStatus_Unknown {
		return errors.New("invalid certificate status")
	}
	return nil
}

// IsExpired returns true if the validity period ended before now
func (m *Certificate) IsExpired(now time.Time) bool {
	return m.NotAfter.UTC().Before(now)
}

// Pb converts model to proto
func (m *Certificate) Pb() *pb.Certificate {
	return &pb.Certificate{
		ID:           m.ID.String(),
		OrgID:        m.OrgID.String(),
		ProjectID:    m.ProjectID.String(),
		SKID:         m.Skid,
		IKID:         m.Ikid,
		SerialNumber: m.SerialNumber,
		NotBefore:    m.NotBefore.String(),
		NotAfter:     m.NotAfter.String(),
		Subject:      m.Subject,
		Issuer:       m.Issuer,
		Sha256:       m.Sha256,
		Profile:      m.Profile,
		Pem:          m.Pem,
		IssuersPem:   m.IssuersPem,
		Locations:    []string(m.Locations),
		Label:        m.Label,
		Metadata:     map[string]string(m.Metadata),
		Status:       m.Status,
		CreatedAt:    m.CreatedAt.String(),
	}
}

// NextPage returns the next page of the result
func (v *CertificateResult) NextPage() *pb.NextPage {
	if v.HasNextPage {
		return &pb.NextPage{
			Offset: v.NextOffset,
			Cursor: v.Cursor,
		}
	}
	return nil
}

// Pb converts model to proto
func (v *CertificateResult) Pb() *pb.CertificatesResponse {
	res := &pb.CertificatesResponse{
		Certificates: make([]*pb.Certificate, len(v.Rows)),
		NextPage:     v.NextPage(),
	}
	for i, r := range v.Rows {
		res.Certificates[i] = r.Pb()
	}
	return res
}
