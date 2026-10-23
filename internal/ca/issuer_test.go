package ca_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"io"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/ca"
	"github.com/effective-security/trustyca/internal/ca/pbconv"
	"github.com/effective-security/trustyca/tests/testutils"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/csr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// xdbID returns the ID
func xdbID(id uint64) xdb.ID {
	return xdb.NewID(id)
}

// storedPEM returns the PEM of a certificate as the rows store it: without
// comments and without a trailing newline
func storedPEM(t *testing.T, crt *x509.Certificate) string {
	t.Helper()
	pem, err := certutil.EncodeToPEMString(false, crt)
	require.NoError(t, err)
	return pem
}

// keyPEM returns the PEM encoding of the key
func keyPEM(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
}

func TestKeys_NewRootIssuer(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	org := xdbID(1)
	profile, err := pbconv.ProfileFromPb(rootProfileDef(rootProfile))
	require.NoError(t, err)
	req := func() *ca.IssuerRequest {
		return &ca.IssuerRequest{
			OrgID:    org,
			Label:    "ROOT",
			Type:     pb.AuthorityType_Root,
			Subject:  &csr.X509Subject{CommonName: "Org Root", Names: []csr.X509Name{{Organization: "Org"}}},
			Provider: f.prov,
			Config:   &pb.IssuerConfig{AllowedProfiles: []string{"CA"}},
		}
	}

	m, err := f.keys.NewRootIssuer(f.ctx, req(), rootProfile, profile)
	require.NoError(t, err)
	assert.Equal(t, org.UInt64(), m.OrgID.UInt64())
	assert.True(t, m.ProjectID.IsZero())
	assert.Equal(t, "ROOT", m.Label)
	assert.Equal(t, pb.AuthorityType_Root, m.Type)
	assert.Equal(t, pb.IssuerStatus_Active, m.Status)
	assert.True(t, m.ParentID.IsZero())
	assert.Empty(t, m.Ikid, "a self-signed root carries no authority key identifier")
	assert.Equal(t, m.Subject, m.Issuer)
	assert.Equal(t, "CN=Org Root,O=Org", m.Subject)
	assert.Equal(t, m.Pem, m.RootPem)
	assert.Empty(t, m.ChainPem)
	assert.Empty(t, m.CsrPem)
	assert.Equal(t, ca.SoftwareKeyProvider, m.KeyProvider)
	assert.Equal(t, "trustyca/1/0/ROOT", m.KeyID)
	assert.NotEmpty(t, m.KeyProtected)
	cfg, err := m.GetConfig()
	require.NoError(t, err)
	assert.Equal(t, []string{"CA"}, cfg.AllowedProfiles)
	require.NoError(t, m.Validate())

	crt, err := certutil.ParseFromPEM([]byte(m.Pem))
	require.NoError(t, err)
	assert.True(t, crt.IsCA)
	assert.Equal(t, -1, crt.MaxPathLen)
	assert.True(t, ca.IsSelfSigned(crt))
	skid, err := ca.SubjectKeyID(crt.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, skid, m.Skid)
	signer, err := f.keys.Signer(f.ctx, m)
	require.NoError(t, err)
	assert.True(t, ca.PublicKeysEqual(crt.PublicKey, signer.Public()))

	// RSA root
	r := req()
	r.KeySpec = &pb.KeySpec{Algo: "RSA", Size: 2048}
	m, err = f.keys.NewRootIssuer(f.ctx, r, rootProfile, profile)
	require.NoError(t, err)
	crt, err = certutil.ParseFromPEM([]byte(m.Pem))
	require.NoError(t, err)
	assert.Equal(t, x509.RSA, crt.PublicKeyAlgorithm)

	// errors
	r = req()
	r.Type = pb.AuthorityType_Issuing
	_, err = f.keys.NewRootIssuer(f.ctx, r, rootProfile, profile)
	assert.EqualError(t, err, "a self-signed issuer is of Root type, not Issuing")
	peer, err := pbconv.ProfileFromPb(peerProfileDef("peer", "*", "1h"))
	require.NoError(t, err)
	_, err = f.keys.NewRootIssuer(f.ctx, req(), "peer", peer)
	assert.EqualError(t, err, `profile "peer" is not a CA profile`)
	_, err = f.keys.NewRootIssuer(f.ctx, req(), "nil", nil)
	assert.EqualError(t, err, `profile "nil" is not a CA profile`)
	r = req()
	r.Subject = &csr.X509Subject{}
	_, err = f.keys.NewRootIssuer(f.ctx, r, rootProfile, profile)
	assert.EqualError(t, err, "subject is required")
	r = req()
	r.Provider = nil
	_, err = f.keys.NewRootIssuer(f.ctx, r, rootProfile, profile)
	assert.EqualError(t, err, "key provider is required")
	r = req()
	r.Label = ""
	_, err = f.keys.NewRootIssuer(f.ctx, r, rootProfile, profile)
	assert.EqualError(t, err, "label is required")
	r = req()
	r.Type = pb.AuthorityType_Unknown
	_, err = f.keys.NewRootIssuer(f.ctx, r, rootProfile, profile)
	assert.EqualError(t, err, "type is required")
	r = req()
	r.KeySpec = &pb.KeySpec{Algo: "DSA"}
	_, err = f.keys.NewRootIssuer(f.ctx, r, rootProfile, profile)
	assert.EqualError(t, err, "unsupported key algorithm: DSA")
	_, err = f.keys.NewRootIssuer(f.ctx, nil, rootProfile, profile)
	assert.EqualError(t, err, "issuer request is required")
}

func TestKeys_NewSignedIssuer(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	org := xdbID(1)
	project := xdbID(201)
	h := f.org(org)

	// the fixture issuer is signed by the root with the CA profile
	m := h.issuer
	assert.Equal(t, h.platformRoot.ID.UInt64(), m.ParentID.UInt64())
	assert.Equal(t, h.platformRoot.Skid, m.Ikid)
	assert.Equal(t, h.platformRoot.Subject, m.Issuer)
	assert.Empty(t, m.ChainPem, "nothing between the issuer and its root")
	assert.Equal(t, h.platformRoot.Pem, m.RootPem)
	assert.Equal(t, pb.AuthorityType_Issuing, m.Type)
	assert.Equal(t, "trustyca/1/0/L2", m.KeyID)
	crt, err := certutil.ParseFromPEM([]byte(m.Pem))
	require.NoError(t, err)
	assert.True(t, crt.IsCA)
	assert.True(t, crt.MaxPathLenZero)
	roots := x509.NewCertPool()
	rootCrt, err := certutil.ParseFromPEM([]byte(h.platformRoot.Pem))
	require.NoError(t, err)
	roots.AddCert(rootCrt)
	_, err = crt.Verify(x509.VerifyOptions{Roots: roots})
	require.NoError(t, err)

	// the issuing CA has path length zero: it signs no subordinate CA, whose
	// certificates would never verify (RFC 5280 section 4.2.1.9)
	f.profile(org, xdb.ID(0), caProfileDef("SUB", issuerLabel))
	subReq := &ca.IssuerRequest{
		OrgID:     org,
		ProjectID: project,
		Label:     "L3",
		Type:      pb.AuthorityType_Issuing,
		Subject:   &csr.X509Subject{CommonName: "L3 CA"},
		Provider:  f.prov,
	}
	refused, err := f.registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org, Profile: "SUB"})
	require.NoError(t, err)
	_, err = f.keys.NewSignedIssuer(f.ctx, subReq, refused)
	assert.EqualError(t, err, `the path length of "CN=L2 CA" disallows a subordinate CA`)

	// an intermediate with path length one signs a project issuer
	f.profile(org, xdb.ID(0), caProfileDefWithPathLen("INT", rootLabel, 1))
	intermediate := f.child(h.platformRoot, "INT", org, xdb.ID(0), "L2INT", pb.AuthorityType_Intermediate, nil)
	f.profile(org, xdb.ID(0), caProfileDef("SUBINT", "L2INT"))
	sub := f.child(intermediate, "SUBINT", org, project, "L3", pb.AuthorityType_Issuing, nil)
	assert.Equal(t, project.UInt64(), sub.ProjectID.UInt64())
	assert.Equal(t, intermediate.ID.UInt64(), sub.ParentID.UInt64())
	assert.Equal(t, intermediate.Skid, sub.Ikid)
	assert.Equal(t, h.platformRoot.Pem, sub.RootPem)
	assert.Equal(t, strings.TrimSpace(intermediate.Pem), strings.TrimSpace(sub.ChainPem), "the parent, not the root")
	assert.Equal(t, "trustyca/1/201/L3", sub.KeyID)

	// the certificates the project issuer signs verify to the root
	f.profile(org, project, peerProfileDef("sub-peer", "L3", "1h"))
	leafRes, err := f.registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org, ProjectID: project, Profile: "sub-peer"})
	require.NoError(t, err)
	leaf, _, err := leafRes.Issuer.Sign(csr.SignRequest{Request: newCSR(t, "leaf.example.com"), Profile: leafRes.ProfileName})
	require.NoError(t, err)
	intermediates := x509.NewCertPool()
	for _, pemCrt := range []string{sub.Pem, intermediate.Pem} {
		c, err := certutil.ParseFromPEM([]byte(pemCrt))
		require.NoError(t, err)
		intermediates.AddCert(c)
	}
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	require.NoError(t, err)

	// the path length of the intermediate is spent: no third level under
	// the project issuer, and no profile that lets a subordinate sign CAs
	f.profile(org, project, caProfileDef("SUB3", "L3"))
	refused, err = f.registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org, ProjectID: project, Profile: "SUB3"})
	require.NoError(t, err)
	subReq.Label = "L4"
	_, err = f.keys.NewSignedIssuer(f.ctx, subReq, refused)
	assert.EqualError(t, err, `the path length of "CN=L3 CA" disallows a subordinate CA`)
	f.profile(org, xdb.ID(0), caProfileDefWithPathLen("WIDE", "L2INT", 1))
	refused, err = f.registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org, Profile: "WIDE"})
	require.NoError(t, err)
	_, err = f.keys.NewSignedIssuer(f.ctx, subReq, refused)
	assert.EqualError(t, err, "the path length 1 of the profile exceeds the 0 the parent chain allows")

	// a deeper chain carries every parent, nearest first, and ends where
	// the most distant constraint ends
	f.profile(org, xdb.ID(0), caProfileDefWithPathLen("INT2", rootLabel, 2))
	deep1 := f.child(h.platformRoot, "INT2", org, xdb.ID(0), "DEEP1", pb.AuthorityType_Intermediate, nil)
	f.profile(org, xdb.ID(0), caProfileDefWithPathLen("MID", "DEEP1", 1))
	deep2 := f.child(deep1, "MID", org, project, "DEEP2", pb.AuthorityType_Intermediate, nil)
	f.profile(org, project, caProfileDef("LAST", "DEEP2"))
	deep3 := f.child(deep2, "LAST", org, project, "DEEP3", pb.AuthorityType_Issuing, nil)
	assert.Equal(t, strings.TrimSpace(deep2.Pem)+"\n"+strings.TrimSpace(deep1.Pem), strings.TrimSpace(deep3.ChainPem))
	assert.Equal(t, h.platformRoot.Pem, deep3.RootPem)
	f.profile(org, project, caProfileDef("LAST4", "DEEP3"))
	refused, err = f.registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org, ProjectID: project, Profile: "LAST4"})
	require.NoError(t, err)
	_, err = f.keys.NewSignedIssuer(f.ctx, subReq, refused)
	assert.EqualError(t, err, `the path length of "CN=DEEP3 CA" disallows a subordinate CA`)

	// the parent must resolve a CA profile
	peer, err := f.registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org, Profile: peerProfile})
	require.NoError(t, err)
	req := &ca.IssuerRequest{
		OrgID:    org,
		Label:    "L4",
		Type:     pb.AuthorityType_Issuing,
		Subject:  &csr.X509Subject{CommonName: "L4"},
		Provider: f.prov,
	}
	_, err = f.keys.NewSignedIssuer(f.ctx, req, peer)
	assert.EqualError(t, err, `profile "peer" is not a CA profile`)
	_, err = f.keys.NewSignedIssuer(f.ctx, req, nil)
	assert.EqualError(t, err, "parent issuer is required")
	_, err = f.keys.NewSignedIssuer(f.ctx, &ca.IssuerRequest{}, peer)
	assert.EqualError(t, err, "label is required")

	// a Root is never signed by a parent: it would be registered as a trust
	// anchor with a certificate that is not self-signed
	caRes, err := f.registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org, Profile: "SUB"})
	require.NoError(t, err)
	req.Type = pb.AuthorityType_Root
	_, err = f.keys.NewSignedIssuer(f.ctx, req, caRes)
	assert.EqualError(t, err, "a Root issuer is self-signed, not signed by a parent")
}

func TestKeys_PendingAndActivate(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	org := xdbID(1)
	h := f.org(org)
	req := &ca.IssuerRequest{
		OrgID:    org,
		Label:    "EXT",
		Type:     pb.AuthorityType_Issuing,
		Subject:  &csr.X509Subject{CommonName: "Externally Signed", Names: []csr.X509Name{{Organization: "Org"}}},
		SAN:      []string{"ca.example.com"},
		Provider: f.prov,
	}
	pending, err := f.keys.NewPendingIssuer(f.ctx, req)
	require.NoError(t, err)
	assert.Equal(t, pb.IssuerStatus_Pending, pending.Status)
	assert.NotEmpty(t, pending.CsrPem)
	assert.Equal(t, "CN=Externally Signed,O=Org", pending.Subject)
	assert.Empty(t, pending.Pem)
	assert.NotEmpty(t, pending.Skid, "the key identifies the issuer")
	require.NoError(t, pending.Validate())
	pending, err = f.db.RegisterIssuer(f.ctx, pending, nil)
	require.NoError(t, err)
	csrReq, err := csr.ParsePEM([]byte(pending.CsrPem))
	require.NoError(t, err)
	assert.Equal(t, []string{"ca.example.com"}, csrReq.DNSNames)

	req.Type = pb.AuthorityType_Root
	_, err = f.keys.NewPendingIssuer(f.ctx, req)
	assert.EqualError(t, err, "a Root issuer is self-signed, not pending")
	_, err = f.keys.NewPendingIssuer(f.ctx, nil)
	assert.EqualError(t, err, "issuer request is required")

	// an external CA, here the org root, signs the request with a CA profile
	root, err := f.registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org, Profile: caProfile, IssuerLabel: rootLabel})
	require.NoError(t, err)
	crt, certPEM, err := root.Issuer.Sign(csr.SignRequest{
		Request: pending.CsrPem,
		Profile: root.ProfileName,
	})
	require.NoError(t, err)
	assert.Equal(t, pending.Skid, certutil.GetSubjectKeyID(crt), "the external certificate keeps the key identifier")

	activated, err := f.keys.ActivatedIssuer(f.ctx, pending, string(certPEM), "", h.platformRoot.Pem)
	require.NoError(t, err)
	assert.Equal(t, pb.IssuerStatus_Pending, activated.Status, "the DB activates the row")
	assert.Equal(t, pending.ID.UInt64(), activated.ID.UInt64())
	assert.Equal(t, h.platformRoot.Skid, activated.Ikid)
	assert.Equal(t, h.platformRoot.Pem, activated.RootPem)
	assert.Empty(t, activated.ChainPem)
	assert.Equal(t, certutil.SHA256Hex(crt.Raw), activated.Sha256)
	assert.Equal(t, pending.CsrPem, activated.CsrPem, "the copy keeps the CSR; the DB clears it")
	row, err := f.db.ActivateIssuer(f.ctx, activated)
	require.NoError(t, err)
	assert.Equal(t, pb.IssuerStatus_Active, row.Status)
	assert.Empty(t, row.CsrPem)

	// the activated issuer signs
	f.profile(org, xdb.ID(0), peerProfileDef("ext-peer", "EXT", "1h"))
	res, err := f.registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org, Profile: "ext-peer"})
	require.NoError(t, err)
	leaf, _, err := res.Issuer.Sign(csr.SignRequest{Request: newCSR(t, "leaf"), Profile: res.ProfileName})
	require.NoError(t, err)
	assert.Equal(t, pending.Skid, certutil.GetAuthorityKeyID(leaf))

	// errors
	_, err = f.keys.ActivatedIssuer(f.ctx, row, string(certPEM), "", h.platformRoot.Pem)
	assert.EqualError(t, err, "issuer is not pending")
	_, err = f.keys.ActivatedIssuer(f.ctx, pending, "junk", "", h.platformRoot.Pem)
	assert.ErrorContains(t, err, "invalid certificate")
	_, err = f.keys.ActivatedIssuer(f.ctx, pending, h.issuer.Pem, "", h.platformRoot.Pem)
	assert.EqualError(t, err, "certificate does not match the key of the issuer")
	_, err = f.keys.ActivatedIssuer(f.ctx, pending, string(certPEM), "", "")
	assert.ErrorContains(t, err, "invalid certificate chain")
	other := testutils.NewTestCA(t, "Other Root", nil)
	_, err = f.keys.ActivatedIssuer(f.ctx, pending, string(certPEM), "", testutils.CertPEM(other.Cert))
	assert.ErrorContains(t, err, "invalid certificate chain")
	leafPEM, err := certutil.EncodeToPEMString(false, leaf)
	require.NoError(t, err)
	_, err = f.keys.ActivatedIssuer(f.ctx, pending, leafPEM, "", h.platformRoot.Pem)
	assert.EqualError(t, err, "certificate is not a CA certificate")
}

func TestKeys_ImportIssuer(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	org := xdbID(1)
	root := testutils.NewTestCA(t, "Import Root", nil)
	l1 := testutils.NewTestCA(t, "Import L1", root)
	l2 := testutils.NewTestCA(t, "Import L2", l1)

	// an issuing CA with its chain and a software key
	m, err := f.keys.ImportIssuer(f.ctx, &ca.ImportRequest{
		OrgID:         org,
		Label:         "BYO",
		Type:          pb.AuthorityType_Issuing,
		Certificate:   testutils.CertPEM(l2.Cert),
		Intermediates: testutils.CertPEM(l1.Cert),
		Root:          testutils.CertPEM(root.Cert),
		KeyPEM:        keyPEM(t, l2.Key),
		Config:        &pb.IssuerConfig{CrlExpiry: "24h"},
	})
	require.NoError(t, err)
	assert.Equal(t, pb.IssuerStatus_Active, m.Status)
	assert.Equal(t, certutil.GetSubjectKeyID(l2.Cert), m.Skid)
	assert.Equal(t, certutil.GetSubjectKeyID(l1.Cert), m.Ikid)
	assert.Equal(t, storedPEM(t, l1.Cert), m.ChainPem)
	assert.Equal(t, storedPEM(t, root.Cert), m.RootPem)
	assert.Equal(t, storedPEM(t, l2.Cert), m.Pem)
	assert.True(t, m.ParentID.IsZero())
	assert.Equal(t, ca.SoftwareKeyProvider, m.KeyProvider)
	assert.Equal(t, "trustyca/1/0/BYO", m.KeyID)
	assert.NotEmpty(t, m.KeyProtected)
	require.NoError(t, m.Validate())
	row, err := f.db.RegisterIssuer(f.ctx, m, nil)
	require.NoError(t, err)
	f.profile(org, xdb.ID(0), peerProfileDef("byo-peer", "BYO", "1h"))
	res, err := f.registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org, Profile: "byo-peer"})
	require.NoError(t, err)
	assert.Equal(t, row.ID.UInt64(), res.Row.ID.UInt64())
	assert.Equal(t, 24*3600, int(res.Issuer.CrlExpiry().Seconds()))
	leaf, _, err := res.Issuer.Sign(csr.SignRequest{Request: newCSR(t, "leaf"), Profile: res.ProfileName})
	require.NoError(t, err)
	assert.Equal(t, l2.Cert.Subject.String(), leaf.Issuer.String())

	// a self-signed root without a root bundle is its own root
	m, err = f.keys.ImportIssuer(f.ctx, &ca.ImportRequest{
		OrgID:       org,
		Label:       "BYO_ROOT",
		Type:        pb.AuthorityType_Root,
		Certificate: testutils.CertPEM(root.Cert),
		KeyPEM:      keyPEM(t, root.Key),
	})
	require.NoError(t, err)
	assert.Equal(t, m.Pem, m.RootPem)
	assert.Empty(t, m.ChainPem)
	assert.Equal(t, certutil.GetSubjectKeyID(root.Cert), m.Skid)
	assert.Equal(t, certutil.GetAuthorityKeyID(root.Cert), m.Ikid, "a self-signed root may carry no authority key identifier")

	// a key by URI
	priv, err := f.prov.GenerateECDSAKey("byo", elliptic.P256())
	require.NoError(t, err)
	keyID, _, err := f.prov.IdentifyKey(priv)
	require.NoError(t, err)
	uriCA := newSelfSignedCA(t, priv.(interface {
		Public() crypto.PublicKey
		Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)
	}), "URI Root")
	m, err = f.keys.ImportIssuer(f.ctx, &ca.ImportRequest{
		OrgID:       org,
		Label:       "URI_ROOT",
		Type:        pb.AuthorityType_Root,
		Certificate: uriCA,
		KeyURI:      inmemURI(f.prov, keyID),
	})
	require.NoError(t, err)
	assert.Equal(t, inmemURI(f.prov, keyID), m.KeyID)
	assert.Empty(t, m.KeyProtected)

	// errors
	tcases := []struct {
		name string
		req  *ca.ImportRequest
		err  string
	}{
		{name: "nil", err: "import request is required"},
		{name: "label", req: &ca.ImportRequest{}, err: "label is required"},
		{name: "type", req: &ca.ImportRequest{Label: "x"}, err: "type is required"},
		{name: "cert", req: &ca.ImportRequest{Label: "x", Type: pb.AuthorityType_Issuing, Certificate: "junk"}, err: "invalid certificate"},
		{name: "not ca", req: &ca.ImportRequest{Label: "x", Type: pb.AuthorityType_Issuing, Certificate: testutils.CertPEM(leaf)}, err: "certificate is not a CA certificate"},
		{name: "root not self-signed", req: &ca.ImportRequest{Label: "x", Type: pb.AuthorityType_Root, Certificate: testutils.CertPEM(l1.Cert), KeyPEM: keyPEM(t, l1.Key)}, err: "a Root issuer certificate is self-signed"},
		{name: "no key", req: &ca.ImportRequest{Label: "x", Type: pb.AuthorityType_Issuing, Certificate: testutils.CertPEM(l2.Cert)}, err: "key is required"},
		{name: "wrong key", req: &ca.ImportRequest{Label: "x", Type: pb.AuthorityType_Issuing, Certificate: testutils.CertPEM(l2.Cert), KeyPEM: keyPEM(t, l1.Key)}, err: "key does not match the certificate"},
		{name: "no root", req: &ca.ImportRequest{Label: "x", Type: pb.AuthorityType_Issuing, Certificate: testutils.CertPEM(l2.Cert), Intermediates: testutils.CertPEM(l1.Cert), KeyPEM: keyPEM(t, l2.Key)}, err: "invalid certificate chain"},
		{name: "wrong root", req: &ca.ImportRequest{Label: "x", Type: pb.AuthorityType_Issuing, Certificate: testutils.CertPEM(l2.Cert), Root: uriCA, KeyPEM: keyPEM(t, l2.Key)}, err: "invalid certificate chain"},
		{name: "bad config", req: &ca.ImportRequest{Label: "x", Type: pb.AuthorityType_Root, Certificate: testutils.CertPEM(root.Cert), KeyPEM: keyPEM(t, root.Key), Config: &pb.IssuerConfig{CrlExpiry: "x"}}, err: `invalid CrlExpiry: "x" is not a duration`},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := f.keys.ImportIssuer(f.ctx, tc.req)
			assert.ErrorContains(t, err, tc.err)
		})
	}
}

// newSelfSignedCA returns the PEM of a self-signed CA certificate for the
// signer, with the key identifier the authority computes
func newSelfSignedCA(t *testing.T, signer crypto.Signer, cn string) string {
	t.Helper()
	skid, err := ca.SubjectKeyID(signer.Public())
	require.NoError(t, err)
	ski, err := hex.DecodeString(skid)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          ski,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
