package model

import (
	"crypto/x509"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xpki/certutil"
)

// NewRootCertificate builds a trust anchor row from the parsed certificate;
// a zero orgID registers a platform root
func NewRootCertificate(crt *x509.Certificate, orgID xdb.ID, trust pb.Trust_Enum, pem string) *RootCertificate {
	return &RootCertificate{
		OrgID:     orgID,
		Skid:      certutil.GetSubjectKeyID(crt),
		NotBefore: xdb.UTC(crt.NotBefore),
		NotAfter:  xdb.UTC(crt.NotAfter),
		Subject:   crt.Subject.String(),
		Sha256:    certutil.SHA256Hex(crt.Raw),
		Trust:     trust,
		Pem:       pem,
	}
}

// Validate returns error if the model is not valid
func (m *RootCertificate) Validate() error {
	if err := validateLength("skid", m.Skid, MaxLenForLabel, true); err != nil {
		return err
	}
	if err := validateLength("subject", m.Subject, MaxLenForName, true); err != nil {
		return err
	}
	if len(m.Sha256) != MaxLenForSha256 {
		return errors.New("invalid sha256 length")
	}
	if m.NotBefore.IsZero() || m.NotAfter.IsZero() || !m.NotAfter.UTC().After(m.NotBefore.UTC()) {
		return errors.New("invalid validity period")
	}
	if m.Pem == "" {
		return errors.New("invalid pem: required")
	}
	return nil
}

// Pb converts model to proto
func (m *RootCertificate) Pb() *pb.RootCertificate {
	return &pb.RootCertificate{
		ID:        m.ID.String(),
		OrgID:     m.OrgID.String(),
		SKID:      m.Skid,
		NotBefore: m.NotBefore.String(),
		NotAfter:  m.NotAfter.String(),
		Subject:   m.Subject,
		Sha256:    m.Sha256,
		Trust:     m.Trust,
		Pem:       m.Pem,
		CreatedAt: m.CreatedAt.String(),
	}
}

// NextPage returns the next page of the result
func (v *RootCertificateResult) NextPage() *pb.NextPage {
	if v.HasNextPage {
		return &pb.NextPage{
			Offset: v.NextOffset,
			Cursor: v.Cursor,
		}
	}
	return nil
}

// Pb converts model to proto
func (v *RootCertificateResult) Pb() *pb.RootsResponse {
	res := &pb.RootsResponse{
		Roots:    make([]*pb.RootCertificate, len(v.Rows)),
		NextPage: v.NextPage(),
	}
	for i, r := range v.Rows {
		res.Roots[i] = r.Pb()
	}
	return res
}
