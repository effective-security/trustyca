package model

import (
	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
)

// Validate returns error if the model is not valid
func (m *Revoked) Validate() error {
	if err := validateTenancy(m.OrgID, m.ProjectID); err != nil {
		return err
	}
	if m.CertificateID.IsZero() {
		return errors.New("invalid certificate ID")
	}
	if err := validateLength("ikid", m.Ikid, MaxLenForLabel, true); err != nil {
		return err
	}
	if err := validateLength("serial number", m.SerialNumber, MaxLenForLabel, true); err != nil {
		return err
	}
	if err := validateLength("reason text", m.ReasonText, MaxLenForName, false); err != nil {
		return err
	}
	if m.NotAfter.IsZero() {
		return errors.New("invalid not after time")
	}
	if m.RevokedAt.IsZero() {
		return errors.New("invalid revocation time")
	}
	return nil
}

// NewRevokedCertificate joins a certificate with its revocation, as the
// vw_revoked_certificate view does
func NewRevokedCertificate(c *Certificate, r *Revoked) *RevokedCertificate {
	return &RevokedCertificate{
		ID:            r.ID,
		OrgID:         r.OrgID,
		ProjectID:     r.ProjectID,
		CertificateID: c.ID,
		Skid:          c.Skid,
		Ikid:          c.Ikid,
		SerialNumber:  c.SerialNumber,
		NotBefore:     c.NotBefore,
		NotAfter:      c.NotAfter,
		Subject:       c.Subject,
		Issuer:        c.Issuer,
		Sha256:        c.Sha256,
		Profile:       c.Profile,
		Label:         c.Label,
		Locations:     c.Locations,
		Metadata:      c.Metadata,
		Pem:           c.Pem,
		IssuersPem:    c.IssuersPem,
		Status:        c.Status,
		CreatedAt:     c.CreatedAt,
		RevokedAt:     r.RevokedAt,
		Reason:        r.Reason,
		ReasonText:    r.ReasonText,
	}
}

// Certificate returns the certificate columns of the row
func (m *RevokedCertificate) Certificate() *Certificate {
	return &Certificate{
		ID:           m.CertificateID,
		OrgID:        m.OrgID,
		ProjectID:    m.ProjectID,
		Skid:         m.Skid,
		Ikid:         m.Ikid,
		SerialNumber: m.SerialNumber,
		NotBefore:    m.NotBefore,
		NotAfter:     m.NotAfter,
		Subject:      m.Subject,
		Issuer:       m.Issuer,
		Sha256:       m.Sha256,
		Profile:      m.Profile,
		Label:        m.Label,
		Locations:    m.Locations,
		Metadata:     m.Metadata,
		Pem:          m.Pem,
		IssuersPem:   m.IssuersPem,
		Status:       m.Status,
		CreatedAt:    m.CreatedAt,
	}
}

// Pb converts model to proto
func (m *RevokedCertificate) Pb() *pb.RevokedCertificate {
	return &pb.RevokedCertificate{
		Certificate: m.Certificate().Pb(),
		RevokedAt:   m.RevokedAt.String(),
		Reason:      m.Reason,
		ReasonText:  m.ReasonText,
	}
}

// NextPage returns the next page of the result
func (v *RevokedCertificateResult) NextPage() *pb.NextPage {
	if v.HasNextPage {
		return &pb.NextPage{
			Offset: v.NextOffset,
			Cursor: v.Cursor,
		}
	}
	return nil
}

// Pb converts model to proto
func (v *RevokedCertificateResult) Pb() *pb.RevokedCertificatesResponse {
	res := &pb.RevokedCertificatesResponse{
		RevokedCertificates: make([]*pb.RevokedCertificate, len(v.Rows)),
		NextPage:            v.NextPage(),
	}
	for i, r := range v.Rows {
		res.RevokedCertificates[i] = r.Pb()
	}
	return res
}

// NextPage returns the next page of the result
func (v *RevokedResult) NextPage() *pb.NextPage {
	if v.HasNextPage {
		return &pb.NextPage{
			Offset: v.NextOffset,
			Cursor: v.Cursor,
		}
	}
	return nil
}
