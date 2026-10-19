package ca_test

import (
	"crypto"
	"crypto/elliptic"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/ca"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/tests/testutils"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xpki/authority"
	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/cryptoprov"
	"github.com/effective-security/xpki/csr"
	"github.com/effective-security/xpki/dataprotection"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeFile writes a fixture file and returns its path
func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))
	return path
}

// bootstrapConfig is a ca-config with a root bundle, a CA bundle of the L1
// and two file issuers under it, L1 and L2, with profiles
func bootstrapConfig(t *testing.T, dir string, root, l1, l2 *testutils.TestCA) *authority.Config {
	t.Helper()
	return &authority.Config{
		Authority: &authority.CAConfig{
			RootsBundleFiles: []string{writeFile(t, dir, "root.pem", testutils.CertPEM(root.Cert))},
			CABundleFiles:    []string{writeFile(t, dir, "cabundle.pem", testutils.CertPEM(l1.Cert))},
			Issuers: []authority.IssuerConfig{
				{
					Label:    "L1",
					CertFile: writeFile(t, dir, "l1.pem", testutils.CertPEM(l1.Cert)),
					KeyFile:  writeFile(t, dir, "l1.key", keyPEM(t, l1.Key)),
				},
				{
					Label:           "L2",
					CertFile:        writeFile(t, dir, "l2.pem", testutils.CertPEM(l2.Cert)),
					KeyFile:         writeFile(t, dir, "l2.key", keyPEM(t, l2.Key)),
					AllowedProfiles: []string{"ocsp"},
					AIA: &authority.AIAConfig{
						CrlURL:               "http://cis/v1/crl/${ISSUER_ID}",
						OCSPExpiry:           time.Hour,
						DelegatedOCSPProfile: "ocsp",
					},
				},
			},
		},
		Profiles: map[string]*authority.CertProfile{
			"peer": {
				IssuerLabel: "L2",
				Expiry:      csr.Duration(168 * time.Hour),
				Backdate:    csr.Duration(30 * time.Minute),
				Usage:       []string{"signing", "server auth", "client auth"},
			},
			"ocsp": {
				IssuerLabel: model.AnyIssuerLabel,
				Expiry:      csr.Duration(168 * time.Hour),
				Usage:       []string{"ocsp signing"},
				OCSPNoCheck: true,
			},
			"ROOT": {
				Expiry:       csr.Duration(10 * 365 * 24 * time.Hour),
				Usage:        []string{"cert sign", "crl sign"},
				CAConstraint: authority.CAConstraint{IsCA: true, MaxPathLen: -1},
			},
		},
	}
}

func TestBootstrap(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	dir := t.TempDir()
	root := testutils.NewTestCA(t, "Boot Root", nil)
	l1 := testutils.NewTestCA(t, "Boot L1", root)
	l2 := testutils.NewTestCA(t, "Boot L2", l1)
	cfg := bootstrapConfig(t, dir, root, l1, l2)

	res, err := f.registry.Bootstrap(f.ctx, f.db, cfg)
	require.NoError(t, err)
	assert.Equal(t, &ca.BootstrapResult{Issuers: 2, Updated: 0, Roots: 1, Profiles: 3}, res)
	assert.Equal(t, 2, f.registry.Len(), "the enabled issuers are loaded at the start")

	// the issuers are platform rows with their chain, settings and key
	row1, err := f.db.FindIssuer(f.ctx, 0, 0, "L1")
	require.NoError(t, err)
	assert.True(t, row1.OrgID.IsZero())
	assert.Equal(t, pb.AuthorityType_Intermediate, row1.Type)
	assert.Equal(t, pb.IssuerStatus_Active, row1.Status)
	assert.True(t, row1.ParentID.IsZero(), "the root is a trust anchor, not an issuer")
	assert.Equal(t, certutil.GetSubjectKeyID(l1.Cert), row1.Skid)
	assert.Equal(t, certutil.GetSubjectKeyID(root.Cert), row1.Ikid)
	assert.Empty(t, row1.ChainPem)
	assert.Equal(t, storedPEM(t, root.Cert), row1.RootPem)
	assert.Equal(t, storedPEM(t, l1.Cert), row1.Pem)
	assert.Equal(t, ca.SoftwareKeyProvider, row1.KeyProvider)
	assert.Equal(t, "trustyca/0/0/L1", row1.KeyID)
	assert.NotEmpty(t, row1.KeyProtected)
	cfg1, err := row1.GetConfig()
	require.NoError(t, err)
	assert.Empty(t, cfg1.AllowedProfiles)

	row2, err := f.db.FindIssuer(f.ctx, 0, 0, "L2")
	require.NoError(t, err)
	assert.Equal(t, row1.ID.UInt64(), row2.ParentID.UInt64(), "the parent registered before it")
	assert.Equal(t, storedPEM(t, l1.Cert), row2.ChainPem)
	assert.Equal(t, storedPEM(t, root.Cert), row2.RootPem)
	cfg2, err := row2.GetConfig()
	require.NoError(t, err)
	assert.Equal(t, []string{"ocsp"}, cfg2.AllowedProfiles)
	assert.Equal(t, "http://cis/v1/crl/${ISSUER_ID}", cfg2.CrlURL)
	assert.Equal(t, "1h0m0s", cfg2.OcspExpiry)
	assert.Equal(t, "ocsp", cfg2.DelegatedOcspProfile)

	// the root and the profiles
	rootRow, err := f.db.RegisterRoot(f.ctx, model.NewRootCertificate(root.Cert, xdb.ID(0), pb.Trust_Private, testutils.CertPEM(root.Cert)))
	require.NoError(t, err)
	assert.True(t, rootRow.OrgID.IsZero())
	assert.Equal(t, 1, f.db.Calls("RegisterRoot")-1, "the bootstrap registered it once")
	peer, err := f.db.FindProfile(f.ctx, 0, 0, "peer")
	require.NoError(t, err)
	assert.Equal(t, "L2", peer.IssuerLabel)
	rootProfile, err := f.db.FindProfile(f.ctx, 0, 0, "ROOT")
	require.NoError(t, err)
	assert.Equal(t, model.AnyIssuerLabel, rootProfile.IssuerLabel, "a self-signing profile binds to any issuer")

	// the registry signs with the bootstrapped issuer and its delegated responder
	resolved, err := f.registry.Resolve(f.ctx, &ca.ResolveRequest{Profile: "peer"})
	require.NoError(t, err)
	assert.Equal(t, row2.ID.UInt64(), resolved.Row.ID.UInt64())
	assert.Equal(t, "http://cis/v1/crl/"+row2.Skid, resolved.Issuer.CrlURL())
	leaf, _, err := resolved.Issuer.Sign(csr.SignRequest{Request: newCSR(t, "leaf"), Profile: resolved.ProfileName})
	require.NoError(t, err)
	assert.Equal(t, l2.Cert.Subject.String(), leaf.Issuer.String())
	_, err = resolved.Issuer.SignOCSP(&authority.OCSPSignRequest{SerialNumber: leaf.SerialNumber, Status: authority.OCSPStatusGood, IssuerHash: crypto.SHA1})
	require.NoError(t, err)

	// a second run changes nothing
	f.db.ResetCalls()
	res, err = f.registry.Bootstrap(f.ctx, f.db, cfg)
	require.NoError(t, err)
	assert.Equal(t, &ca.BootstrapResult{Issuers: 0, Updated: 0, Roots: 1, Profiles: 3}, res)
	assert.Equal(t, 0, f.db.Calls("RegisterIssuer"))
	assert.Equal(t, 0, f.db.Calls("UpdateIssuer"))

	// changed settings are refreshed
	cfg.Authority.Issuers[1].AIA.CrlURL = "http://cis2/v1/crl/${ISSUER_ID}"
	res, err = f.registry.Bootstrap(f.ctx, f.db, cfg)
	require.NoError(t, err)
	assert.Equal(t, 1, res.Updated)
	assert.Equal(t, 0, res.Issuers)
	assert.Equal(t, "http://cis2/v1/crl/${ISSUER_ID}", f.db.configJSON(row2.ID)["CrlURL"])

	// a disabled issuer is archived: it stops signing on this instance and
	// on a restarted one, and signs again once the configuration enables it
	disabled := true
	cfg.Authority.Issuers[1].Disabled = &disabled
	res, err = f.registry.Bootstrap(f.ctx, f.db, cfg)
	require.NoError(t, err)
	assert.Equal(t, &ca.BootstrapResult{Archived: 1, Roots: 1, Profiles: 3}, res)
	row2, err = f.db.FindIssuer(f.ctx, 0, 0, "L2")
	require.NoError(t, err)
	assert.Equal(t, pb.IssuerStatus_Archived, row2.Status)
	_, err = f.registry.Resolve(f.ctx, &ca.ResolveRequest{Profile: "peer"})
	assert.ErrorIs(t, err, ca.ErrIssuerNotActive)
	restarted := ca.NewRegistry(f.db, f.keys, ca.Options{})
	res, err = restarted.Bootstrap(f.ctx, f.db, cfg)
	require.NoError(t, err)
	assert.Equal(t, &ca.BootstrapResult{Roots: 1, Profiles: 3}, res, "an archived issuer stays archived")
	_, err = restarted.Resolve(f.ctx, &ca.ResolveRequest{Profile: "peer"})
	assert.ErrorIs(t, err, ca.ErrIssuerNotActive)
	assert.Equal(t, 1, restarted.Len(), "only the enabled issuer is loaded")
	cfg.Authority.Issuers[1].Disabled = nil
	res, err = f.registry.Bootstrap(f.ctx, f.db, cfg)
	require.NoError(t, err)
	assert.Equal(t, &ca.BootstrapResult{Updated: 1, Roots: 1, Profiles: 3}, res, "the issuer is enabled again")
	resolved, err = f.registry.Resolve(f.ctx, &ca.ResolveRequest{Profile: "peer"})
	require.NoError(t, err)
	assert.Equal(t, pb.IssuerStatus_Active, resolved.Row.Status)
	assert.Equal(t, "http://cis2/v1/crl/"+row2.Skid, resolved.Issuer.CrlURL(), "the refreshed settings")

	// an issuer that does not load fails the start: a delegated OCSP profile
	// that does not exist is the issuer's failure, not a missing profile
	cfg.Authority.Issuers[1].AIA.DelegatedOCSPProfile = "nope"
	_, err = f.registry.Bootstrap(f.ctx, f.db, cfg)
	assert.ErrorContains(t, err, `issuer "L2": delegated OCSP profile "nope" of issuer `)
	assert.ErrorContains(t, err, "is not found")
	assert.NotErrorIs(t, err, ca.ErrProfileNotFound)
	cfg.Authority.Issuers[1].AIA.DelegatedOCSPProfile = "ocsp"
	res, err = f.registry.Bootstrap(f.ctx, f.db, cfg)
	require.NoError(t, err)
	assert.Equal(t, 1, res.Updated)
	// a key that another data protection provider wrapped does not load
	otherDP, err := dataprotection.NewSymmetric([]byte("rotated-seed"))
	require.NoError(t, err)
	crypto, err := cryptoprov.New(f.prov, nil)
	require.NoError(t, err)
	rotated := ca.NewRegistry(f.db, ca.NewKeys(crypto, otherDP), ca.Options{})
	_, err = rotated.Bootstrap(f.ctx, f.db, cfg)
	assert.ErrorContains(t, err, `issuer "L1": `)
	assert.Equal(t, 0, rotated.Len())

	// a renewed certificate with a new key is refused
	l2b := testutils.NewTestCA(t, "Boot L2 v2", l1)
	writeFile(t, dir, "l2.pem", testutils.CertPEM(l2b.Cert))
	writeFile(t, dir, "l2.key", keyPEM(t, l2b.Key))
	_, err = f.registry.Bootstrap(f.ctx, f.db, cfg)
	assert.ErrorContains(t, err, `issuer "L2": the certificate is for key `+certutil.GetSubjectKeyID(l2b.Cert))
	assert.ErrorContains(t, err, "archive the registered issuer under another label")
	writeFile(t, dir, "l2.pem", testutils.CertPEM(l2.Cert))
	writeFile(t, dir, "l2.key", keyPEM(t, l2.Key))

	// a key that is not the certificate's is refused
	l3 := testutils.NewTestCA(t, "Boot L3", l1)
	cfg.Authority.Issuers = append(cfg.Authority.Issuers, authority.IssuerConfig{
		Label:    "L3",
		CertFile: writeFile(t, dir, "l3.pem", testutils.CertPEM(l3.Cert)),
		KeyFile:  writeFile(t, dir, "l3.key", keyPEM(t, l2.Key)),
	})
	_, err = f.registry.Bootstrap(f.ctx, f.db, cfg)
	assert.EqualError(t, errors.Cause(err), "key does not match the certificate")
	assert.ErrorContains(t, err, `issuer "L3": `)

	// an issuer whose chain does not verify is refused
	other := testutils.NewTestCA(t, "Other Root", nil)
	otherL1 := testutils.NewTestCA(t, "Other L1", other)
	cfg.Authority.Issuers[2] = authority.IssuerConfig{
		Label:    "L3",
		CertFile: writeFile(t, dir, "l3.pem", testutils.CertPEM(otherL1.Cert)),
		KeyFile:  writeFile(t, dir, "l3.key", keyPEM(t, otherL1.Key)),
	}
	_, err = f.registry.Bootstrap(f.ctx, f.db, cfg)
	assert.ErrorContains(t, err, `issuer "L3": invalid certificate chain`)

	// missing files and labels
	cfg.Authority.Issuers[2] = authority.IssuerConfig{Label: "L3", CertFile: filepath.Join(dir, "nope.pem")}
	_, err = f.registry.Bootstrap(f.ctx, f.db, cfg)
	assert.ErrorContains(t, err, `issuer "L3": unable to read certificate`)
	cfg.Authority.Issuers[2] = authority.IssuerConfig{Label: "L3", CertFile: filepath.Join(dir, "l3.pem"), KeyFile: filepath.Join(dir, "nope.key")}
	_, err = f.registry.Bootstrap(f.ctx, f.db, cfg)
	assert.ErrorContains(t, err, `issuer "L3": unable to read key`)
	cfg.Authority.Issuers[2] = authority.IssuerConfig{CertFile: filepath.Join(dir, "l3.pem")}
	_, err = f.registry.Bootstrap(f.ctx, f.db, cfg)
	assert.ErrorContains(t, err, `issuer "": label is required`)
	cfg.Authority.Issuers = cfg.Authority.Issuers[:2]

	// an invalid profile and a DB failure fail the bootstrap
	cfg.Profiles["bad"] = &authority.CertProfile{IssuerLabel: "L2"}
	_, err = f.registry.Bootstrap(f.ctx, f.db, cfg)
	assert.ErrorContains(t, err, `profile "bad"`)
	delete(cfg.Profiles, "bad")
	f.db.Err = errors.New("db down")
	_, err = f.registry.Bootstrap(f.ctx, f.db, cfg)
	assert.ErrorContains(t, err, "db down")
	f.db.Err = nil
	_, err = f.registry.Bootstrap(f.ctx, f.db, nil)
	assert.EqualError(t, err, "authority configuration is required")

	// a destroyed issuer has no key: the configuration cannot enable it
	_, err = f.db.UpdateIssuer(f.ctx, &query.UpdateIssuerRequest{ID: row2.ID.UInt64(), Status: pb.IssuerStatus_Destroyed})
	require.NoError(t, err)
	_, err = f.registry.Bootstrap(f.ctx, f.db, cfg)
	assert.EqualError(t, errors.Cause(err), "the registered issuer is Destroyed: register it under another label")
	assert.ErrorContains(t, err, `issuer "L2": `)

	// a configuration without issuers registers its profiles
	res, err = f.registry.Bootstrap(f.ctx, f.db, &authority.Config{Profiles: cfg.Profiles})
	require.NoError(t, err)
	assert.Equal(t, &ca.BootstrapResult{Profiles: 3}, res)
}

func TestBootstrap_ProviderKey(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	dir := t.TempDir()

	// a root whose key a crypto provider holds, referenced by its URI
	priv, err := f.prov.GenerateECDSAKey("boot-root", elliptic.P256())
	require.NoError(t, err)
	keyID, _, err := f.prov.IdentifyKey(priv)
	require.NoError(t, err)
	signer := priv.(crypto.Signer)
	rootPEM := newSelfSignedCA(t, signer, "Provider Root")
	cfg := &authority.Config{
		Authority: &authority.CAConfig{
			Issuers: []authority.IssuerConfig{{
				Label:    "PROOT",
				CertFile: writeFile(t, dir, "root.pem", rootPEM),
				KeyFile:  writeFile(t, dir, "root.key", inmemURI(f.prov, keyID)+"\n"),
			}},
		},
		Profiles: map[string]*authority.CertProfile{
			"CA": {
				IssuerLabel:  "PROOT",
				Expiry:       csr.Duration(8760 * time.Hour),
				Usage:        []string{"cert sign", "crl sign"},
				CAConstraint: authority.CAConstraint{IsCA: true, MaxPathLen: 0},
			},
		},
	}
	res, err := f.registry.Bootstrap(f.ctx, f.db, cfg)
	require.NoError(t, err)
	assert.Equal(t, &ca.BootstrapResult{Issuers: 1, Roots: 1, Profiles: 1}, res, "a root issuer is also a trust anchor")
	assert.Equal(t, 1, f.db.rootCount())

	// the anchor is registered again on every start, so an anchor an earlier
	// start failed to write is repaired
	f.db.clearRoots()
	res, err = f.registry.Bootstrap(f.ctx, f.db, cfg)
	require.NoError(t, err)
	assert.Equal(t, &ca.BootstrapResult{Roots: 1, Profiles: 1}, res)
	assert.Equal(t, 1, f.db.rootCount())

	row, err := f.db.FindIssuer(f.ctx, 0, 0, "PROOT")
	require.NoError(t, err)
	assert.Equal(t, pb.AuthorityType_Root, row.Type)
	assert.Equal(t, inmemURI(f.prov, keyID), row.KeyID)
	assert.Equal(t, f.prov.Manufacturer(), row.KeyProvider)
	assert.Empty(t, row.KeyProtected, "a provider key is never stored")
	assert.Equal(t, row.Pem, row.RootPem)
	assert.Empty(t, row.ChainPem)

	// a tenant issuer is signed by the platform root through the registry
	resolved, err := f.registry.Resolve(f.ctx, &ca.ResolveRequest{Profile: "CA", IssuerLabel: "PROOT"})
	require.NoError(t, err)
	child, err := f.keys.NewSignedIssuer(f.ctx, &ca.IssuerRequest{
		OrgID:    xdb.NewID(1),
		Label:    "TENANT",
		Type:     pb.AuthorityType_Issuing,
		Subject:  &csr.X509Subject{CommonName: "Tenant CA"},
		Provider: f.prov,
	}, resolved)
	require.NoError(t, err)
	assert.Equal(t, row.ID.UInt64(), child.ParentID.UInt64())
	assert.Equal(t, row.Skid, child.Ikid)
	assert.Equal(t, row.Pem, child.RootPem)
}
