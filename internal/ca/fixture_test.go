package ca_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
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
	"github.com/effective-security/xpki/cryptoprov"
	"github.com/effective-security/xpki/cryptoprov/inmemcrypto"
	"github.com/effective-security/xpki/csr"
	"github.com/effective-security/xpki/dataprotection"
	"github.com/stretchr/testify/require"
)

// Labels of the fixtures
const (
	rootProfile  = "ROOT"
	caProfile    = "CA"
	peerProfile  = "peer"
	ocspProfile  = "ocsp"
	rootLabel    = "ROOT"
	issuerLabel  = "L2"
	csrPEMType   = "CERTIFICATE REQUEST"
	testDPSecret = "fixture-seed"
)

// fixture is a CA over the fake DB, the inmem crypto provider and a
// symmetric data protection provider
type fixture struct {
	t        testing.TB
	ctx      context.Context
	db       *fakeDb
	prov     cryptoprov.Provider
	keys     *ca.Keys
	registry *ca.Registry
}

func newFixture(t testing.TB) *fixture {
	t.Helper()
	prov := inmemcrypto.NewProvider()
	crypto, err := cryptoprov.New(prov, nil)
	require.NoError(t, err)
	dp, err := dataprotection.NewSymmetric([]byte(testDPSecret))
	require.NoError(t, err)
	fdb := newFakeDb()
	keys := ca.NewKeys(crypto, dp)
	return &fixture{
		t:        t,
		ctx:      context.Background(),
		db:       fdb,
		prov:     prov,
		keys:     keys,
		registry: ca.NewRegistry(fdb, keys, ca.Options{}),
	}
}

// rootProfileDef is a self-signing CA profile
func rootProfileDef(label string) *pb.CertProfile {
	return &pb.CertProfile{
		Label:       label,
		IssuerLabel: model.AnyIssuerLabel,
		Expiry:      "43800h",
		Backdate:    "30m",
		Usages:      []string{"cert sign", "crl sign"},
		CAConstraint: &pb.CAConstraint{
			IsCA:       true,
			MaxPathLen: -1,
		},
	}
}

// caProfileDef is the profile a parent signs issuing CAs with: the CAs get
// path length zero and sign no subordinate CA
func caProfileDef(label, issuerLabel string) *pb.CertProfile {
	return caProfileDefWithPathLen(label, issuerLabel, 0)
}

// caProfileDefWithPathLen is the profile a parent signs subordinate CAs
// with the path length: the number of CAs they may sign in turn
func caProfileDefWithPathLen(label, issuerLabel string, maxPathLen int32) *pb.CertProfile {
	return &pb.CertProfile{
		Label:       label,
		IssuerLabel: issuerLabel,
		Expiry:      "8760h",
		Backdate:    "30m",
		Usages:      []string{"cert sign", "crl sign"},
		CAConstraint: &pb.CAConstraint{
			IsCA:       true,
			MaxPathLen: maxPathLen,
		},
	}
}

// peerProfileDef is an end-entity profile
func peerProfileDef(label, issuerLabel, expiry string) *pb.CertProfile {
	return &pb.CertProfile{
		Label:       label,
		IssuerLabel: issuerLabel,
		Expiry:      expiry,
		Backdate:    "30m",
		Usages:      []string{"signing", "key encipherment", "server auth", "client auth"},
		AllowedExtensions: []string{
			"2.5.29.17",
		},
	}
}

// ocspProfileDef is a delegated OCSP responder profile for any issuer
func ocspProfileDef(label string) *pb.CertProfile {
	return &pb.CertProfile{
		Label:       label,
		IssuerLabel: model.AnyIssuerLabel,
		Expiry:      "168h",
		Backdate:    "30m",
		Usages:      []string{"ocsp signing"},
		OcspNoCheck: true,
	}
}

// profile registers a profile of the scope
func (f *fixture) profile(orgID, projectID xdb.ID, def *pb.CertProfile) *model.CertificateProfile {
	f.t.Helper()
	m, err := model.NewCertificateProfile(orgID, projectID, def)
	require.NoError(f.t, err)
	res, err := f.db.RegisterProfile(f.ctx, m)
	require.NoError(f.t, err)
	return res
}

// root creates and registers a self-signed root of the scope
func (f *fixture) root(orgID, projectID xdb.ID, label string, cfg *pb.IssuerConfig) *model.Issuer {
	f.t.Helper()
	profile, err := pbconv.ProfileFromPb(rootProfileDef(rootProfile))
	require.NoError(f.t, err)
	m, err := f.keys.NewRootIssuer(f.ctx, &ca.IssuerRequest{
		OrgID:     orgID,
		ProjectID: projectID,
		Label:     label,
		Type:      pb.AuthorityType_Root,
		Subject:   &csr.X509Subject{CommonName: label + " Root"},
		Provider:  f.prov,
		Config:    cfg,
	}, rootProfile, profile)
	require.NoError(f.t, err)
	res, err := f.db.RegisterIssuer(f.ctx, m, nil)
	require.NoError(f.t, err)
	return res
}

// child creates and registers an issuer of the scope signed by the parent
// with the CA profile of the parent's scope
func (f *fixture) child(parent *model.Issuer, caProfileLabel string, orgID, projectID xdb.ID, label string, typ pb.AuthorityType_Enum, cfg *pb.IssuerConfig) *model.Issuer {
	f.t.Helper()
	res, err := f.registry.Resolve(f.ctx, &ca.ResolveRequest{
		OrgID:       parent.OrgID,
		ProjectID:   parent.ProjectID,
		Profile:     caProfileLabel,
		IssuerLabel: parent.Label,
	})
	require.NoError(f.t, err)
	m, err := f.keys.NewSignedIssuer(f.ctx, &ca.IssuerRequest{
		OrgID:     orgID,
		ProjectID: projectID,
		Label:     label,
		Type:      typ,
		Subject:   &csr.X509Subject{CommonName: label + " CA"},
		Provider:  f.prov,
		Config:    cfg,
	}, res)
	require.NoError(f.t, err)
	row, err := f.db.RegisterIssuer(f.ctx, m, nil)
	require.NoError(f.t, err)
	return row
}

// hierarchy registers the platform root and CA profile, and for the org an
// issuing CA signed by the platform root with the org's peer profile
type hierarchy struct {
	platformRoot *model.Issuer
	issuer       *model.Issuer
	peer         *model.CertificateProfile
}

// org registers a root and an issuing CA of the org with its peer profile;
// the issuer label is issuerLabel in every org, so that the tests exercise
// equal labels in different orgs
func (f *fixture) org(orgID xdb.ID) *hierarchy {
	f.t.Helper()
	f.profile(orgID, xdb.ID(0), caProfileDef(caProfile, rootLabel))
	root := f.root(orgID, xdb.ID(0), rootLabel, nil)
	issuer := f.child(root, caProfile, orgID, xdb.ID(0), issuerLabel, pb.AuthorityType_Issuing, &pb.IssuerConfig{
		AllowedProfiles: []string{ocspProfile},
	})
	peer := f.profile(orgID, xdb.ID(0), peerProfileDef(peerProfile, issuerLabel, "168h"))
	return &hierarchy{
		platformRoot: root,
		issuer:       issuer,
		peer:         peer,
	}
}

// newCSR returns the PEM encoding of a certificate request for a new key
func newCSR(t testing.TB, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}, key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: csrPEMType, Bytes: der}))
}
