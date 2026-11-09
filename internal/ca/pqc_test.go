package ca_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/ca"
	"github.com/effective-security/trustyca/internal/ca/pbconv"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xpki/authority"
	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/csr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"
)

// Labels of the post-quantum fixtures
const (
	pqPeerProfile      = "pq-peer"
	classicPeerProfile = "classic-peer"
	pqOCSPURL          = "http://cis.example.com/v1/ocsp/${ISSUER_ID}"
)

// newECDSAKey returns a new P-256 key
func newECDSAKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

// newMLDSAKey returns a new ML-DSA-65 key
func newMLDSAKey(t testing.TB) *mldsa.PrivateKey {
	t.Helper()
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	return key
}

// newMLDSACSR returns the PEM encoding of a certificate request for a new
// ML-DSA-65 key
func newMLDSACSR(t testing.TB, cn string) string {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}, newMLDSAKey(t))
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: csrPEMType, Bytes: der}))
}

// mldsaKeyPEM returns the PKCS#8 PEM of an ML-DSA key, in the seed form
func mldsaKeyPEM(t testing.TB, key *mldsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// ocspConfig returns the settings of an issuer that publishes OCSP through
// a delegated responder, as an ML-DSA issuer must
func ocspConfig(allowed ...string) *pb.IssuerConfig {
	return &pb.IssuerConfig{
		AllowedProfiles:      append([]string{ocspProfile}, allowed...),
		DelegatedOcspProfile: ocspProfile,
		OcspURL:              pqOCSPURL,
		OcspExpiry:           "1h",
		CrlExpiry:            "48h",
	}
}

// pqPeerProfileDef is an end-entity profile that signs ML-DSA keys only
func pqPeerProfileDef(issuerLabel string) *pb.CertProfile {
	def := peerProfileDef(pqPeerProfile, issuerLabel, "1h")
	def.AllowedKeyAlgorithms = []string{"ml-dsa"}
	return def
}

// classicPeerProfileDef is an end-entity profile that signs ECDSA keys only
func classicPeerProfileDef(issuerLabel string) *pb.CertProfile {
	def := peerProfileDef(classicPeerProfile, issuerLabel, "1h")
	def.AllowedKeyAlgorithms = []string{"ECDSA"}
	return def
}

// TestPostQuantum_Hierarchy issues an ML-DSA root, an ML-DSA issuing CA it
// signs, the leaves of the issuing CA under profiles that restrict the key
// algorithm, its delegated OCSP responses and its CRL
func TestPostQuantum_Hierarchy(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	org := xdbID(7)
	f.profile(org, xdb.ID(0), caProfileDef(caProfile, rootLabel))
	f.profile(org, xdb.ID(0), ocspProfileDef(ocspProfile))
	rootProfileDefinition, err := pbconv.ProfileFromPb(rootProfileDef(rootProfile))
	require.NoError(t, err)

	// an ML-DSA-87 root with a delegated OCSP responder
	rootReq := &ca.IssuerRequest{
		OrgID:    org,
		Label:    rootLabel,
		Type:     pb.AuthorityType_Root,
		Subject:  &csr.X509Subject{CommonName: "PQ Root"},
		KeySpec:  &pb.KeySpec{Algo: "ML-DSA", Size: 87},
		Provider: f.prov,
		Config:   ocspConfig(caProfile),
	}
	rootRow, err := f.keys.NewRootIssuer(f.ctx, rootReq, rootProfile, rootProfileDefinition)
	require.NoError(t, err)
	rootCert, err := certutil.ParseFromPEM([]byte(rootRow.Pem))
	require.NoError(t, err)
	assert.Equal(t, x509.MLDSA, rootCert.PublicKeyAlgorithm)
	assert.Equal(t, x509.MLDSA87, rootCert.SignatureAlgorithm)
	assert.True(t, certutil.IsPostQuantumCertificate(rootCert))
	assert.True(t, ca.IsSelfSigned(rootCert))
	assert.Equal(t, x509.KeyUsageCertSign|x509.KeyUsageCRLSign, rootCert.KeyUsage)
	assert.Equal(t, ca.SoftwareKeyProvider, rootRow.KeyProvider)
	assert.NotEmpty(t, rootRow.KeyProtected, "the inmem key is stored wrapped")
	skid, err := ca.SubjectKeyID(rootCert.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, skid, rootRow.Skid)
	rootSigner, err := f.keys.Signer(f.ctx, rootRow)
	require.NoError(t, err)
	assert.True(t, ca.PublicKeysEqual(rootCert.PublicKey, rootSigner.Public()), "the wrapped key loads")
	rootRow, err = f.db.RegisterIssuer(f.ctx, rootRow, model.NewRootCertificate(rootCert, org, pb.Trust_Private, rootRow.Pem))
	require.NoError(t, err)

	// an ML-DSA-65 issuing CA the root signs
	parent, err := f.registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org, Profile: caProfile, IssuerLabel: rootLabel})
	require.NoError(t, err)
	issuerRow, err := f.keys.NewSignedIssuer(f.ctx, &ca.IssuerRequest{
		OrgID:    org,
		Label:    issuerLabel,
		Type:     pb.AuthorityType_Issuing,
		Subject:  &csr.X509Subject{CommonName: "PQ Issuing CA"},
		KeySpec:  &pb.KeySpec{Algo: "mldsa", Size: 65},
		Provider: f.prov,
		Config:   ocspConfig(),
	}, parent)
	require.NoError(t, err)
	issuerCert, err := certutil.ParseFromPEM([]byte(issuerRow.Pem))
	require.NoError(t, err)
	assert.Equal(t, x509.MLDSA, issuerCert.PublicKeyAlgorithm)
	assert.Equal(t, x509.MLDSA87, issuerCert.SignatureAlgorithm, "signed by the root")
	assert.Equal(t, x509.KeyUsageCertSign|x509.KeyUsageCRLSign, issuerCert.KeyUsage)
	require.NoError(t, issuerCert.CheckSignatureFrom(rootCert))
	assert.Equal(t, rootRow.Skid, issuerRow.Ikid)
	issuerRow, err = f.db.RegisterIssuer(f.ctx, issuerRow, nil)
	require.NoError(t, err)

	// the profiles restrict the key algorithm of the requests
	f.profile(org, xdb.ID(0), pqPeerProfileDef(issuerLabel))
	f.profile(org, xdb.ID(0), classicPeerProfileDef(issuerLabel))
	pq, err := f.registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org, Profile: pqPeerProfile})
	require.NoError(t, err)
	assert.Equal(t, issuerRow.ID.UInt64(), pq.Row.ID.UInt64())
	assert.Equal(t, "http://cis.example.com/v1/ocsp/"+issuerRow.Skid, pq.Issuer.OcspURL())
	leaf, _, err := pq.Issuer.Sign(csr.SignRequest{Request: newMLDSACSR(t, "pq.example.com"), Profile: pq.ProfileName})
	require.NoError(t, err)
	assert.Equal(t, x509.MLDSA, leaf.PublicKeyAlgorithm)
	assert.Equal(t, x509.MLDSA65, leaf.SignatureAlgorithm)
	assert.Equal(t, x509.KeyUsageDigitalSignature, leaf.KeyUsage)
	require.NoError(t, leaf.CheckSignatureFrom(issuerCert))
	assert.Equal(t, issuerRow.Skid, certutil.GetAuthorityKeyID(leaf))
	_, _, err = pq.Issuer.Sign(csr.SignRequest{Request: newCSR(t, "classic.example.com"), Profile: pq.ProfileName})
	assert.ErrorContains(t, err, "public key algorithm ECDSA is not allowed by profile "+pq.ProfileName)

	classic, err := f.registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org, Profile: classicPeerProfile})
	require.NoError(t, err)
	leaf, _, err = classic.Issuer.Sign(csr.SignRequest{Request: newCSR(t, "classic.example.com"), Profile: classic.ProfileName})
	require.NoError(t, err)
	assert.Equal(t, x509.ECDSA, leaf.PublicKeyAlgorithm, "an ML-DSA issuer signs classical keys")
	assert.Equal(t, x509.MLDSA65, leaf.SignatureAlgorithm)
	_, _, err = classic.Issuer.Sign(csr.SignRequest{Request: newMLDSACSR(t, "pq.example.com"), Profile: classic.ProfileName})
	assert.ErrorContains(t, err, "public key algorithm ML-DSA is not allowed by profile "+classic.ProfileName)

	// the delegated responder, with a classical key, signs the OCSP responses
	der, err := pq.Issuer.SignOCSP(&authority.OCSPSignRequest{
		SerialNumber: leaf.SerialNumber,
		Status:       authority.OCSPStatusGood,
		IssuerHash:   crypto.SHA1,
	})
	require.NoError(t, err)
	resp, err := ocsp.ParseResponse(der, issuerCert)
	require.NoError(t, err)
	require.NotNil(t, resp.Certificate, "a delegated responder certificate")
	assert.Equal(t, x509.ECDSA, resp.Certificate.PublicKeyAlgorithm)
	assert.Equal(t, x509.MLDSA65, resp.Certificate.SignatureAlgorithm, "the issuer signed the responder certificate")
	assert.Equal(t, x509.KeyUsageDigitalSignature, resp.Certificate.KeyUsage)
	assert.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}, resp.Certificate.ExtKeyUsage)
	assert.Equal(t, ocsp.Good, resp.Status)

	// the issuer signs its CRL
	pub := ca.NewCrlPublisher(f.db, f.registry)
	crl, published, err := pub.PublishCrl(f.ctx, issuerRow, false)
	require.NoError(t, err)
	assert.True(t, published)
	list := parseCRL(t, crl, issuerRow)
	assert.Equal(t, x509.MLDSA65, list.SignatureAlgorithm)
	assert.EqualValues(t, 1, list.Number.Int64())

	// a classical issuer the ML-DSA root signs: its certificate carries an
	// ML-DSA signature, but its key is ECDSA, and its responder signs OCSP
	ecOCSP := ocspConfig()
	pending, err := f.keys.NewPendingIssuer(f.ctx, &ca.IssuerRequest{
		OrgID:    org,
		Label:    "EC_UNDER_PQ",
		Type:     pb.AuthorityType_Issuing,
		Subject:  &csr.X509Subject{CommonName: "EC under PQ"},
		Provider: f.prov,
		Config:   ecOCSP,
	})
	require.NoError(t, err)
	pending, err = f.db.RegisterIssuer(f.ctx, pending, nil)
	require.NoError(t, err)
	ecCert, ecPEM, err := parent.Issuer.Sign(csr.SignRequest{Request: pending.CsrPem, Profile: parent.ProfileName})
	require.NoError(t, err)
	assert.Equal(t, x509.ECDSA, ecCert.PublicKeyAlgorithm)
	assert.Equal(t, x509.MLDSA87, ecCert.SignatureAlgorithm)
	assert.True(t, certutil.IsPostQuantumCertificate(ecCert), "the chain is mixed")
	activated, err := f.keys.ActivatedIssuer(f.ctx, pending, string(ecPEM), "", rootRow.Pem)
	require.NoError(t, err)
	_, err = f.db.ActivateIssuer(f.ctx, activated)
	require.NoError(t, err)
	f.profile(org, xdb.ID(0), peerProfileDef("ec-peer", "EC_UNDER_PQ", "1h"))
	ec, err := f.registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org, Profile: "ec-peer"})
	require.NoError(t, err)
	der, err = ec.Issuer.SignOCSP(&authority.OCSPSignRequest{
		SerialNumber: leaf.SerialNumber,
		Status:       authority.OCSPStatusGood,
		IssuerHash:   crypto.SHA1,
	})
	require.NoError(t, err)
	resp, err = ocsp.ParseResponse(der, ecCert)
	require.NoError(t, err)
	require.NotNil(t, resp.Certificate, "the delegated responder signed the response")
	assert.Equal(t, x509.KeyUsageCertSign|x509.KeyUsageCRLSign, ecCert.KeyUsage, "the CA key signs no OCSP response")

	// the same for an import of such an issuer
	ecKey := newECDSAKey(t)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "EC import under PQ"}}, ecKey)
	require.NoError(t, err)
	_, byoPEM, err := parent.Issuer.Sign(csr.SignRequest{
		Request: string(pem.EncodeToMemory(&pem.Block{Type: csrPEMType, Bytes: csrDER})),
		Profile: parent.ProfileName,
	})
	require.NoError(t, err)
	imported, err := f.keys.ImportIssuer(f.ctx, &ca.ImportRequest{
		OrgID:       org,
		Label:       "EC_BYO_UNDER_PQ",
		Type:        pb.AuthorityType_Issuing,
		Certificate: string(byoPEM),
		Root:        rootRow.Pem,
		KeyPEM:      keyPEM(t, ecKey),
		Config:      ecOCSP,
	})
	require.NoError(t, err)
	assert.Equal(t, rootRow.Skid, imported.Ikid)
}

// TestPostQuantum_OCSPSigner checks that an issuer with an OCSP URL and no
// delegated responder is refused when it is created, imported or activated,
// before its key exists, and accepted with the responder
func TestPostQuantum_OCSPSigner(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	org := xdbID(8)
	h := f.org(org)
	f.profile(org, xdb.ID(0), ocspProfileDef(ocspProfile))
	rootProfileDefinition, err := pbconv.ProfileFromPb(rootProfileDef(rootProfile))
	require.NoError(t, err)
	noResponder := &pb.IssuerConfig{OcspURL: pqOCSPURL}
	request := func(label string, typ pb.AuthorityType_Enum, cfg *pb.IssuerConfig) *ca.IssuerRequest {
		return &ca.IssuerRequest{
			OrgID:    org,
			Label:    label,
			Type:     typ,
			Subject:  &csr.X509Subject{CommonName: label},
			KeySpec:  &pb.KeySpec{Algo: "ML-DSA", Size: 44},
			Provider: f.prov,
			Config:   cfg,
		}
	}
	parent, err := f.registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org, Profile: caProfile, IssuerLabel: rootLabel})
	require.NoError(t, err)

	_, err = f.keys.NewRootIssuer(f.ctx, request("PQ_ROOT", pb.AuthorityType_Root, noResponder), rootProfile, rootProfileDefinition)
	assert.ErrorIs(t, err, ca.ErrOCSPSignerRequired)
	_, err = f.keys.NewSignedIssuer(f.ctx, request("PQ_L2", pb.AuthorityType_Issuing, noResponder), parent)
	assert.ErrorIs(t, err, ca.ErrOCSPSignerRequired)
	_, err = f.keys.NewPendingIssuer(f.ctx, request("PQ_EXT", pb.AuthorityType_Issuing, noResponder))
	assert.ErrorIs(t, err, ca.ErrOCSPSignerRequired)
	assert.EqualError(t, err, "an issuer with an OCSP URL needs a delegated responder: set DelegatedOcspProfile or remove OcspURL")

	// nor does a classical key sign OCSP
	classic := request("EC_EXT", pb.AuthorityType_Issuing, noResponder)
	classic.KeySpec = nil
	_, err = f.keys.NewPendingIssuer(f.ctx, classic)
	assert.ErrorIs(t, err, ca.ErrOCSPSignerRequired)

	// without an OCSP URL no responder is needed
	noOCSP := request("PQ_NO_OCSP", pb.AuthorityType_Issuing, &pb.IssuerConfig{CrlExpiry: "24h"})
	_, err = f.keys.NewPendingIssuer(f.ctx, noOCSP)
	require.NoError(t, err)

	// an externally signed ML-DSA issuer with a delegated responder: the
	// request keeps the responder profile for the registry, and the
	// activation verifies the chain without it
	pending, err := f.keys.NewPendingIssuer(f.ctx, request("PQ_EXT", pb.AuthorityType_Issuing, ocspConfig()))
	require.NoError(t, err)
	pending, err = f.db.RegisterIssuer(f.ctx, pending, nil)
	require.NoError(t, err)
	crt, certPEM, err := parent.Issuer.Sign(csr.SignRequest{Request: pending.CsrPem, Profile: parent.ProfileName})
	require.NoError(t, err)
	assert.Equal(t, x509.MLDSA, crt.PublicKeyAlgorithm)
	activated, err := f.keys.ActivatedIssuer(f.ctx, pending, string(certPEM), "", h.platformRoot.Pem)
	require.NoError(t, err)
	row, err := f.db.ActivateIssuer(f.ctx, activated)
	require.NoError(t, err)
	f.profile(org, xdb.ID(0), peerProfileDef("ext-peer", "PQ_EXT", "1h"))
	res, err := f.registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org, Profile: "ext-peer"})
	require.NoError(t, err)
	assert.Equal(t, row.ID.UInt64(), res.Row.ID.UInt64())
	assert.NotNil(t, res.Issuer.Profile(ocspProfile), "the delegated profile is registered")
	leaf, _, err := res.Issuer.Sign(csr.SignRequest{Request: newCSR(t, "leaf"), Profile: res.ProfileName})
	require.NoError(t, err)
	assert.Equal(t, x509.MLDSA44, leaf.SignatureAlgorithm)

	// the activation of a pending issuer whose settings lost the responder
	pending2, err := f.keys.NewPendingIssuer(f.ctx, request("PQ_EXT2", pb.AuthorityType_Issuing, nil))
	require.NoError(t, err)
	require.NoError(t, pending2.SetConfig(noResponder))
	_, certPEM, err = parent.Issuer.Sign(csr.SignRequest{Request: pending2.CsrPem, Profile: parent.ProfileName})
	require.NoError(t, err)
	_, err = f.keys.ActivatedIssuer(f.ctx, pending2, string(certPEM), "", h.platformRoot.Pem)
	assert.ErrorIs(t, err, ca.ErrOCSPSignerRequired)
	// an imported ML-DSA root
	key := newMLDSAKey(t)
	rootPEM := newSelfSignedCA(t, key, "PQ Import Root")
	_, err = f.keys.ImportIssuer(f.ctx, &ca.ImportRequest{
		OrgID:       org,
		Label:       "PQ_BYO",
		Type:        pb.AuthorityType_Root,
		Certificate: rootPEM,
		KeyPEM:      mldsaKeyPEM(t, key),
		Config:      noResponder,
	})
	assert.ErrorIs(t, err, ca.ErrOCSPSignerRequired)
	imported, err := f.keys.ImportIssuer(f.ctx, &ca.ImportRequest{
		OrgID:       org,
		Label:       "PQ_BYO",
		Type:        pb.AuthorityType_Root,
		Certificate: rootPEM,
		KeyPEM:      mldsaKeyPEM(t, key),
		Config:      ocspConfig(),
	})
	require.NoError(t, err)
	assert.Equal(t, imported.Pem, imported.RootPem)
	assert.Equal(t, ca.SoftwareKeyProvider, imported.KeyProvider)
	importedCert, err := certutil.ParseFromPEM([]byte(imported.Pem))
	require.NoError(t, err)
	imported, err = f.db.RegisterIssuer(f.ctx, imported, model.NewRootCertificate(importedCert, org, pb.Trust_Private, imported.Pem))
	require.NoError(t, err)
	f.profile(org, xdb.ID(0), pqPeerProfileDef("PQ_BYO"))
	byo, err := f.registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org, Profile: pqPeerProfile, IssuerLabel: "PQ_BYO"})
	require.NoError(t, err)
	assert.Equal(t, imported.ID.UInt64(), byo.Row.ID.UInt64())

	leaf, _, err = byo.Issuer.Sign(csr.SignRequest{Request: newMLDSACSR(t, "byo.example.com"), Profile: byo.ProfileName})
	require.NoError(t, err)
	assert.Equal(t, x509.MLDSA65, leaf.SignatureAlgorithm)
	require.NoError(t, leaf.CheckSignatureFrom(importedCert))
}

func TestCheckOCSPSigner(t *testing.T) {
	t.Parallel()
	tcases := []struct {
		name string
		cfg  *pb.IssuerConfig
		err  error
	}{
		{name: "nil config"},
		{name: "no ocsp", cfg: &pb.IssuerConfig{CrlExpiry: "24h"}},
		{name: "delegated", cfg: &pb.IssuerConfig{OcspURL: pqOCSPURL, DelegatedOcspProfile: ocspProfile}},
		{name: "self-signed ocsp", cfg: &pb.IssuerConfig{OcspURL: pqOCSPURL}, err: ca.ErrOCSPSignerRequired},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			err := ca.CheckOCSPSigner(tc.cfg)
			if tc.err != nil {
				assert.ErrorIs(t, err, tc.err)
				return
			}
			assert.NoError(t, err)
		})
	}
}
