package ca

import (
	"bytes"
	"cmp"
	"context"
	"crypto"
	"crypto/x509"
	"slices"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xpki/authority"
	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/cryptoprov"
	"github.com/effective-security/xpki/csr"
)

// IssuerRequest describes an issuer to create: its scope and identity, the
// key to generate and its runtime settings (DESIGN.md section 5.2). The
// certificate request is built from Subject, SAN and Extensions.
type IssuerRequest struct {
	// OrgID is the owning org; zero is the platform
	OrgID xdb.ID
	// ProjectID is the owning project; zero is the org scope
	ProjectID xdb.ID
	// Label of the issuer, unique in its scope
	Label string
	// Type of the authority
	Type pb.AuthorityType_Enum
	// Subject of the issuer certificate; a common name or names are required
	Subject *csr.X509Subject
	// SAN of the issuer certificate
	SAN []string
	// Extensions of the issuer certificate
	Extensions []csr.X509Extension
	// KeySpec of the key to generate; nil takes the defaults
	KeySpec *pb.KeySpec
	// Provider generates and holds the key
	Provider cryptoprov.Provider
	// Config provides the runtime settings of the issuer
	Config *pb.IssuerConfig
}

// validate checks the fields every shape of issuer needs
func (q *IssuerRequest) validate() error {
	if q == nil {
		return errors.New("issuer request is required")
	}
	if q.Label == "" {
		return errors.New("label is required")
	}
	if q.Type == pb.AuthorityType_Unknown {
		return errors.New("type is required")
	}
	if q.Subject == nil || (q.Subject.CommonName == "" && len(q.Subject.Names) == 0) {
		return errors.New("subject is required")
	}
	if q.Provider == nil {
		return errors.New("key provider is required")
	}
	return nil
}

// keyLabel is the label of the key in the provider
func (q *IssuerRequest) keyLabel() string {
	return KeyLabel(q.OrgID, q.ProjectID, q.Label)
}

// certificateRequest returns the request of the issuer certificate, without
// its key request
func (q *IssuerRequest) certificateRequest() *csr.CertificateRequest {
	return &csr.CertificateRequest{
		CommonName:   q.Subject.CommonName,
		Names:        slices.Clone(q.Subject.Names),
		SerialNumber: q.Subject.SerialNumber,
		SAN:          slices.Clone(q.SAN),
		Extensions:   slices.Clone(q.Extensions),
	}
}

// row returns the issuer row of the request with the status, the key
// reference and the runtime settings; the certificate columns are the
// caller's
func (q *IssuerRequest) row(status pb.IssuerStatus_Enum, ref *KeyRef) (*model.Issuer, error) {
	m := &model.Issuer{
		OrgID:     q.OrgID,
		ProjectID: q.ProjectID,
		Label:     q.Label,
		Type:      q.Type,
		Status:    status,
	}
	ref.Apply(m)
	err := m.SetConfig(q.Config)
	if err != nil {
		return nil, err
	}
	return m, nil
}

// NewRootIssuer generates the key of a self-signed root in the provider and
// signs its certificate with the CA profile, registered under profileName.
// The row is Active and its own trust anchor; the caller registers the root
// certificate.
func (k *Keys) NewRootIssuer(ctx context.Context, req *IssuerRequest, profileName string, profile *authority.CertProfile) (*model.Issuer, error) {
	err := req.validate()
	if err != nil {
		return nil, err
	}
	if req.Type != pb.AuthorityType_Root {
		return nil, errors.Errorf("a self-signed issuer is of Root type, not %s", req.Type.String())
	}
	if profile == nil || !profile.CAConstraint.IsCA {
		return nil, errors.Errorf("profile %q is not a CA profile", profileName)
	}
	algo, size, err := KeySpec(req.KeySpec)
	if err != nil {
		return nil, err
	}
	keyLabel := req.keyLabel()
	creq := req.certificateRequest()
	creq.KeyRequest = csr.NewKeyRequest(req.Provider, keyLabel, algo, size, csr.SigningKey)
	cfg := &authority.Config{
		Profiles: map[string]*authority.CertProfile{
			profileName: profile,
		},
	}
	certPEM, _, key, err := authority.NewRoot(profileName, cfg, req.Provider, creq)
	if err != nil {
		return nil, errors.WithMessage(err, "unable to create root certificate")
	}
	ref, err := k.KeyRefFromExport(ctx, req.Provider, keyLabel, key)
	if err != nil {
		return nil, err
	}
	crt, err := certutil.ParseFromPEM(certPEM)
	if err != nil {
		return nil, errors.WithMessage(err, "invalid root certificate")
	}
	m, err := req.row(pb.IssuerStatus_Active, ref)
	if err != nil {
		return nil, err
	}
	pem, err := certutil.EncodeToPEMString(false, crt)
	if err != nil {
		return nil, errors.WithMessage(err, "unable to encode root certificate")
	}
	m.SetCertificate(crt, pem, "", pem)
	return m, nil
}

// NewSignedIssuer generates the key of an issuer in the provider and has the
// parent sign its certificate with the CA profile the parent resolved. The
// row is Active, with the parent as its parent, the parent and its chain as
// its chain and the parent's root as its root. A Root is refused: it is
// self-signed by NewRootIssuer. The chain of the parent must allow a
// subordinate CA with the path length of the profile (checkPathLength), or
// the certificates the subordinate issues would never verify.
func (k *Keys) NewSignedIssuer(ctx context.Context, req *IssuerRequest, parent *Resolution) (*model.Issuer, error) {
	err := req.validate()
	if err != nil {
		return nil, err
	}
	if parent == nil || parent.Issuer == nil || parent.Row == nil || parent.Profile == nil {
		return nil, errors.New("parent issuer is required")
	}
	if !parent.Profile.CAConstraint.IsCA {
		return nil, errors.Errorf("profile %q is not a CA profile", parent.ProfileRow.Label)
	}
	if req.Type == pb.AuthorityType_Root {
		// a Root is its own trust anchor: a certificate a parent signed must
		// never be registered as one
		return nil, errors.New("a Root issuer is self-signed, not signed by a parent")
	}
	err = checkPathLength(parent.Issuer.Bundle(), parent.Profile)
	if err != nil {
		return nil, err
	}
	csrPEM, _, ref, err := k.Generate(ctx, req.Provider, req.keyLabel(), req.KeySpec, req.certificateRequest())
	if err != nil {
		return nil, err
	}
	crt, _, err := parent.Issuer.Sign(csr.SignRequest{
		Request:    string(csrPEM),
		Profile:    parent.ProfileName,
		SAN:        req.SAN,
		Subject:    req.Subject,
		Extensions: req.Extensions,
	})
	if err != nil {
		return nil, errors.WithMessage(err, "unable to sign issuer certificate")
	}
	m, err := req.row(pb.IssuerStatus_Active, ref)
	if err != nil {
		return nil, err
	}
	// the parent row is shared with other requests: the new row gets its
	// own ID value, not the parent's cached one
	m.ParentID = xdb.NewID(parent.Row.ID.UInt64())
	pem, err := certutil.EncodeToPEMString(false, crt)
	if err != nil {
		return nil, errors.WithMessage(err, "unable to encode issuer certificate")
	}
	// the chain holds the CA certificates between the issuer and the root:
	// the parent and its chain, nothing when the parent is the root
	chain := parent.Issuer.PEM()
	if IsSelfSigned(parent.Issuer.Bundle().Cert) {
		chain = ""
	}
	m.SetCertificate(crt, pem, chain, cmp.Or(parent.Row.RootPem, parent.Row.Pem))
	return m, nil
}

// checkPathLength verifies that the chain of the parent allows a subordinate
// CA with the path length of the profile (RFC 5280 section 4.2.1.9). The
// pathLenConstraint of a CA bounds the CA certificates that may follow it
// in a path, so every ancestor with one must allow the subordinate, and the
// CAs the profile lets the subordinate sign in turn; otherwise the leaf
// certificates of the subordinate never verify. The ancestors are walked
// by issuer, so the order of the bundle does not matter.
func checkPathLength(bundle *certutil.Bundle, profile *authority.CertProfile) error {
	if bundle == nil || bundle.Cert == nil {
		return errors.New("parent certificate is required")
	}
	// remaining is the number of CAs that may follow the subordinate in a
	// path; negative while no ancestor constrains it
	remaining := -1
	crt := bundle.Cert
	for distance := 1; crt != nil && distance <= len(bundle.Chain)+2; distance++ {
		if n, ok := pathLenConstraint(crt); ok {
			allowed := n - distance
			if allowed < 0 {
				return errors.Errorf("the path length of %q disallows a subordinate CA", crt.Subject.String())
			}
			if remaining < 0 || allowed < remaining {
				remaining = allowed
			}
		}
		if IsSelfSigned(crt) {
			break
		}
		crt = certutil.FindIssuer(crt, bundle.Chain, bundle.RootCert)
	}
	if p := profile.CAConstraint.MaxPathLen; p >= 0 && remaining >= 0 && p > remaining {
		return errors.Errorf("the path length %d of the profile exceeds the %d the parent chain allows", p, remaining)
	}
	return nil
}

// pathLenConstraint returns the pathLenConstraint of a CA certificate and
// whether it has one: Go tells zero from absent with MaxPathLenZero
func pathLenConstraint(crt *x509.Certificate) (int, bool) {
	if !crt.BasicConstraintsValid || !crt.IsCA {
		return 0, false
	}
	if crt.MaxPathLen > 0 || (crt.MaxPathLen == 0 && crt.MaxPathLenZero) {
		return crt.MaxPathLen, true
	}
	return 0, false
}

// NewPendingIssuer generates the key of an issuer in the provider and its
// certificate request. The row is Pending with the CSR until ActivatedIssuer
// sets the certificate signed outside the CA.
func (k *Keys) NewPendingIssuer(ctx context.Context, req *IssuerRequest) (*model.Issuer, error) {
	err := req.validate()
	if err != nil {
		return nil, err
	}
	if req.Type == pb.AuthorityType_Root {
		return nil, errors.New("a Root issuer is self-signed, not pending")
	}
	creq := req.certificateRequest()
	csrPEM, signer, ref, err := k.Generate(ctx, req.Provider, req.keyLabel(), req.KeySpec, creq)
	if err != nil {
		return nil, err
	}
	m, err := req.row(pb.IssuerStatus_Pending, ref)
	if err != nil {
		return nil, err
	}
	// the key identifies the issuer until its certificate does
	m.Skid, err = SubjectKeyID(signer.Public())
	if err != nil {
		return nil, err
	}
	m.CsrPem = string(csrPEM)
	m.Subject = creq.Name().String()
	return m, nil
}

// ImportRequest describes an issuer imported with an existing certificate
// and key: bring your own CA
type ImportRequest struct {
	// OrgID is the owning org; zero is the platform
	OrgID xdb.ID
	// ProjectID is the owning project; zero is the org scope
	ProjectID xdb.ID
	// Label of the issuer, unique in its scope
	Label string
	// Type of the authority
	Type pb.AuthorityType_Enum
	// Certificate is the PEM encoded issuer certificate
	Certificate string
	// Intermediates are the PEM encoded intermediate CA certificates
	Intermediates string
	// Root is the PEM encoded root; empty for a self-signed certificate
	Root string
	// KeyURI references the key in a crypto provider
	KeyURI string
	// KeyPEM is the PEM encoded key, stored wrapped
	KeyPEM string
	// Config provides the runtime settings of the issuer
	Config *pb.IssuerConfig
}

// ImportIssuer verifies the certificate chain and the key of an imported
// issuer and returns its Active row; the chain and root columns hold the
// verified chain
func (k *Keys) ImportIssuer(ctx context.Context, req *ImportRequest) (*model.Issuer, error) {
	if req == nil {
		return nil, errors.New("import request is required")
	}
	if req.Label == "" {
		return nil, errors.New("label is required")
	}
	if req.Type == pb.AuthorityType_Unknown {
		return nil, errors.New("type is required")
	}
	crt, err := certutil.ParseFromPEM([]byte(req.Certificate))
	if err != nil {
		return nil, errors.WithMessage(err, "invalid certificate")
	}
	if !crt.IsCA {
		return nil, errors.New("certificate is not a CA certificate")
	}
	if req.Type == pb.AuthorityType_Root && !IsSelfSigned(crt) {
		return nil, errors.New("a Root issuer certificate is self-signed")
	}
	signer, ref, err := k.ImportKey(ctx, req.KeyURI, []byte(req.KeyPEM), KeyLabel(req.OrgID, req.ProjectID, req.Label), crt.PublicKey)
	if err != nil {
		return nil, err
	}
	m := &model.Issuer{
		OrgID:     req.OrgID,
		ProjectID: req.ProjectID,
		Label:     req.Label,
		Type:      req.Type,
		Status:    pb.IssuerStatus_Active,
	}
	ref.Apply(m)
	err = m.SetConfig(req.Config)
	if err != nil {
		return nil, err
	}
	err = setVerifiedCertificate(m, req.Config, crt, req.Intermediates, req.Root, signer)
	if err != nil {
		return nil, err
	}
	return m, nil
}

// ActivatedIssuer returns the copy of a Pending row with the certificate
// signed outside the CA, after verifying that the certificate is for the
// key of the issuer and that its chain verifies; the DB activates the row
func (k *Keys) ActivatedIssuer(ctx context.Context, row *model.Issuer, certPEM, intermediates, rootPEM string) (*model.Issuer, error) {
	if row == nil || row.Status != pb.IssuerStatus_Pending {
		return nil, errors.New("issuer is not pending")
	}
	crt, err := certutil.ParseFromPEM([]byte(certPEM))
	if err != nil {
		return nil, errors.WithMessage(err, "invalid certificate")
	}
	if !crt.IsCA {
		return nil, errors.New("certificate is not a CA certificate")
	}
	signer, err := k.Signer(ctx, row)
	if err != nil {
		return nil, err
	}
	if !PublicKeysEqual(signer.Public(), crt.PublicKey) {
		return nil, errors.New("certificate does not match the key of the issuer")
	}
	cfg, err := row.GetConfig()
	if err != nil {
		return nil, err
	}
	m := *row
	err = setVerifiedCertificate(&m, cfg, crt, intermediates, rootPEM, signer)
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// IsSelfSigned reports whether the certificate is its own issuer
func IsSelfSigned(crt *x509.Certificate) bool {
	return crt.IsCA &&
		bytes.Equal(crt.RawIssuer, crt.RawSubject) &&
		crt.CheckSignatureFrom(crt) == nil
}

// setVerifiedCertificate verifies the chain of the certificate the way the
// registry builds the issuer, and sets the certificate columns of the row
// with the chain and the root the verification found; a self-signed
// certificate is its own root. The delegated OCSP profile is not checked
// here: the registry resolves it when it builds the issuer.
func setVerifiedCertificate(m *model.Issuer, cfg *pb.IssuerConfig, crt *x509.Certificate, intermediates, rootPEM string, signer crypto.Signer) error {
	certPEM, err := certutil.EncodeToPEMString(false, crt)
	if err != nil {
		return errors.WithMessage(err, "unable to encode certificate")
	}
	acfg, err := IssuerConfigFromPb(m.Label, cfg)
	if err != nil {
		return err
	}
	acfg.AIA.DelegatedOCSPProfile = ""
	issuer, err := createIssuer(acfg, []byte(certPEM), []byte(intermediates), []byte(rootPEM), signer)
	if err != nil {
		return errors.WithMessage(err, "invalid certificate chain")
	}
	bundle := issuer.Bundle()
	root := certPEM
	if !IsSelfSigned(crt) {
		if bundle.RootCert == nil {
			return errors.New("invalid certificate chain: no trust root")
		}
		root, err = certutil.EncodeToPEMString(false, bundle.RootCert)
		if err != nil {
			return errors.WithMessage(err, "unable to encode root certificate")
		}
	}
	m.SetCertificate(crt, certPEM, bundle.CACertsPEM, root)
	return nil
}
