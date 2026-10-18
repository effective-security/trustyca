package model

import (
	"crypto/x509"
	"strconv"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xpki/certutil"
)

// Validate returns error if the model is not valid.
// A Pending issuer needs its CSR; any other status needs the certificate.
func (m *Issuer) Validate() error {
	if err := validateTenancy(m.OrgID, m.ProjectID); err != nil {
		return err
	}
	if err := validateLength("label", m.Label, MaxLenForLabel, true); err != nil {
		return err
	}
	if m.Type == pb.AuthorityType_Unknown {
		return errors.New("invalid issuer type")
	}
	if m.Status == pb.IssuerStatus_Unknown {
		return errors.New("invalid issuer status")
	}
	if err := validateLength("skid", m.Skid, MaxLenForLabel, true); err != nil {
		return err
	}
	if err := validateLength("key provider", m.KeyProvider, MaxLenForLabel, true); err != nil {
		return err
	}
	if err := validateLength("key ID", m.KeyID, MaxLenForName, true); err != nil {
		return err
	}
	if m.Status == pb.IssuerStatus_Pending {
		if m.CsrPem == "" {
			return errors.New("invalid csr: required for a pending issuer")
		}
		return validateLength("subject", m.Subject, MaxLenForName, true)
	}
	return m.validateCertificate()
}

// validateCertificate checks the certificate columns of an issued issuer
func (m *Issuer) validateCertificate() error {
	if err := validateLength("ikid", m.Ikid, MaxLenForLabel, false); err != nil {
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
	if m.NotBefore.IsZero() || m.NotAfter.IsZero() || !m.NotAfter.UTC().After(m.NotBefore.UTC()) {
		return errors.New("invalid validity period")
	}
	if m.Pem == "" {
		return errors.New("invalid pem: required")
	}
	return nil
}

// SetCertificate sets the certificate columns from the parsed certificate and
// the PEM encodings of the certificate, its intermediates and its root.
// The status is not changed: a Pending issuer is activated by the DB.
func (m *Issuer) SetCertificate(crt *x509.Certificate, pem, chainPem, rootPem string) {
	m.Skid = certutil.GetSubjectKeyID(crt)
	m.Ikid = certutil.GetAuthorityKeyID(crt)
	m.SerialNumber = crt.SerialNumber.String()
	m.Subject = crt.Subject.String()
	m.Issuer = crt.Issuer.String()
	m.Sha256 = certutil.SHA256Hex(crt.Raw)
	m.NotBefore = xdb.UTC(crt.NotBefore)
	m.NotAfter = xdb.UTC(crt.NotAfter)
	m.Pem = pem
	m.ChainPem = chainPem
	m.RootPem = rootPem
}

// SetConfig stores the runtime settings; nil clears them
func (m *Issuer) SetConfig(cfg *pb.IssuerConfig) error {
	if cfg == nil {
		m.Config = nil
		return nil
	}
	j, err := MarshalJSONValue(cfg)
	if err != nil {
		return err
	}
	m.Config = j
	return nil
}

// GetConfig returns the runtime settings; an empty column returns an empty
// message, never nil
func (m *Issuer) GetConfig() (*pb.IssuerConfig, error) {
	cfg := new(pb.IssuerConfig)
	err := m.Config.Unmarshal(cfg)
	if err != nil {
		return nil, errors.WithMessagef(err, "invalid config of issuer %s", m.ID.String())
	}
	return cfg, nil
}

// Pb converts model to proto; the key ID and the protected key material are
// never returned
func (m *Issuer) Pb() (*pb.Issuer, error) {
	cfg, err := m.GetConfig()
	if err != nil {
		return nil, err
	}
	return &pb.Issuer{
		ID:            m.ID.String(),
		OrgID:         m.OrgID.String(),
		ProjectID:     m.ProjectID.String(),
		Label:         m.Label,
		Type:          m.Type,
		Status:        m.Status,
		ParentID:      m.ParentID.String(),
		SKID:          m.Skid,
		IKID:          m.Ikid,
		SerialNumber:  m.SerialNumber,
		Subject:       m.Subject,
		Issuer:        m.Issuer,
		Sha256:        m.Sha256,
		NotBefore:     m.NotBefore.String(),
		NotAfter:      m.NotAfter.String(),
		Certificate:   m.Pem,
		Intermediates: m.ChainPem,
		Root:          m.RootPem,
		Csr:           m.CsrPem,
		KeyProvider:   m.KeyProvider,
		Config:        cfg,
		CrlNumber:     strconv.FormatInt(m.CrlNumber, 10),
		CreatedAt:     m.CreatedAt.String(),
		UpdatedAt:     m.UpdatedAt.String(),
	}, nil
}

// NextPage returns the next page of the result
func (v *IssuerResult) NextPage() *pb.NextPage {
	if v.HasNextPage {
		return &pb.NextPage{
			Offset: v.NextOffset,
			Cursor: v.Cursor,
		}
	}
	return nil
}

// Pb converts model to proto
func (v *IssuerResult) Pb() (*pb.IssuersResponse, error) {
	res := &pb.IssuersResponse{
		Issuers:  make([]*pb.Issuer, len(v.Rows)),
		NextPage: v.NextPage(),
	}
	for i, r := range v.Rows {
		issuer, err := r.Pb()
		if err != nil {
			return nil, err
		}
		res.Issuers[i] = issuer
	}
	return res, nil
}
