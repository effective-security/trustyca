package ca_test

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/ca"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xpki/authority"
	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/csr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"
)

func TestRegistry_Resolve_Tenancy(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	org1, org2 := xdb.NewID(1), xdb.NewID(2)
	h1 := f.org(org1)
	h2 := f.org(org2)
	require.NotEqual(t, h1.issuer.Skid, h2.issuer.Skid)
	require.Equal(t, h1.issuer.Label, h2.issuer.Label, "equal labels in different orgs")

	// each org resolves its own issuer under the same label
	res1, err := f.registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org1, Profile: peerProfile})
	require.NoError(t, err)
	assert.Equal(t, h1.issuer.ID.UInt64(), res1.Row.ID.UInt64())
	assert.Equal(t, h1.issuer.Skid, res1.Issuer.SubjectKID())
	assert.Equal(t, h1.peer.ID.UInt64(), res1.ProfileRow.ID.UInt64())
	assert.Equal(t, csr.Duration(168*time.Hour), res1.Profile.Expiry)
	assert.NotEmpty(t, res1.ProfileName)

	res2, err := f.registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org2, Profile: peerProfile})
	require.NoError(t, err)
	assert.Equal(t, h2.issuer.ID.UInt64(), res2.Row.ID.UInt64())
	assert.Equal(t, h2.issuer.Skid, res2.Issuer.SubjectKID())
	assert.NotSame(t, res1.Issuer, res2.Issuer)

	// the resolved issuer signs with the resolved profile
	crt, _, err := res1.Issuer.Sign(csr.SignRequest{
		Request: newCSR(t, "a.example.com"),
		Profile: res1.ProfileName,
		SAN:     []string{"a.example.com"},
	})
	require.NoError(t, err)
	assert.Equal(t, h1.issuer.Subject, crt.Issuer.String())
	assert.Equal(t, h1.issuer.Skid, certutil.GetAuthorityKeyID(crt))
	assert.Equal(t, []string{"a.example.com"}, crt.DNSNames)

	// a profile of another org is not found
	f.profile(org2, xdb.ID(0), peerProfileDef("only2", issuerLabel, "1h"))
	_, err = f.registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org1, Profile: "only2"})
	assert.ErrorIs(t, err, ca.ErrProfileNotFound)

	// an issuer of another org is not found through a profile that names it
	f.child(h2.platformRoot, caProfile, org2, xdb.ID(0), "L9", pb.AuthorityType_Issuing, nil)
	f.profile(org1, xdb.ID(0), peerProfileDef("nine", "L9", "1h"))
	_, err = f.registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org1, Profile: "nine"})
	assert.ErrorIs(t, err, ca.ErrIssuerNotFound)

	// platform rows are not visible to tenants
	f.profile(xdb.ID(0), xdb.ID(0), peerProfileDef("platform-only", issuerLabel, "1h"))
	_, err = f.registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org1, Profile: "platform-only"})
	assert.ErrorIs(t, err, ca.ErrProfileNotFound)

	// the platform scope resolves platform rows, for the parents of tenant issuers
	f.profile(xdb.ID(0), xdb.ID(0), caProfileDef("PCA", "PROOT"))
	proot := f.root(xdb.ID(0), xdb.ID(0), "PROOT", nil)
	pres, err := f.registry.Resolve(f.ctx, &ca.ResolveRequest{Profile: "PCA", IssuerLabel: "PROOT"})
	require.NoError(t, err)
	assert.Equal(t, proot.ID.UInt64(), pres.Row.ID.UInt64())
	assert.True(t, pres.Profile.CAConstraint.IsCA)
}

func TestRegistry_Resolve_ProjectScope(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	org := xdb.NewID(1)
	project, other := xdb.NewID(201), xdb.NewID(202)
	h := f.org(org)

	// the org profile serves a project without its own
	res, err := f.registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org, ProjectID: project, Profile: peerProfile})
	require.NoError(t, err)
	assert.Equal(t, h.peer.ID.UInt64(), res.ProfileRow.ID.UInt64())
	assert.Equal(t, h.issuer.ID.UInt64(), res.Row.ID.UInt64())

	// a project profile shadows the org one with its own definition
	pp := f.profile(org, project, peerProfileDef(peerProfile, issuerLabel, "24h"))
	f.registry.InvalidateProfile(org, project, peerProfile)
	res, err = f.registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org, ProjectID: project, Profile: peerProfile})
	require.NoError(t, err)
	assert.Equal(t, pp.ID.UInt64(), res.ProfileRow.ID.UInt64())
	assert.Equal(t, csr.Duration(24*time.Hour), res.Profile.Expiry)
	assert.Equal(t, h.issuer.ID.UInt64(), res.Row.ID.UInt64(), "the org issuer serves the project profile")

	// another project still gets the org profile
	res, err = f.registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org, ProjectID: other, Profile: peerProfile})
	require.NoError(t, err)
	assert.Equal(t, h.peer.ID.UInt64(), res.ProfileRow.ID.UInt64())

	// a project issuer with the org's label shadows the org issuer in its project only
	pi := f.child(h.platformRoot, caProfile, org, other, issuerLabel, pb.AuthorityType_Issuing, nil)
	f.registry.InvalidateIssuer(pi)
	res, err = f.registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org, ProjectID: other, Profile: peerProfile})
	require.NoError(t, err)
	assert.Equal(t, pi.ID.UInt64(), res.Row.ID.UInt64())
	assert.Equal(t, pi.Skid, res.Issuer.SubjectKID())
	res, err = f.registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org, ProjectID: project, Profile: peerProfile})
	require.NoError(t, err)
	assert.Equal(t, h.issuer.ID.UInt64(), res.Row.ID.UInt64())
	res, err = f.registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org, Profile: peerProfile})
	require.NoError(t, err)
	assert.Equal(t, h.issuer.ID.UInt64(), res.Row.ID.UInt64())

	// an inactive project profile hides the label in its project
	inactive := peerProfileDef(peerProfile, issuerLabel, "24h")
	inactive.Status = pb.ItemStatus_Inactive
	f.profile(org, project, inactive)
	f.registry.InvalidateProfile(org, project, peerProfile)
	_, err = f.registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org, ProjectID: project, Profile: peerProfile})
	assert.ErrorIs(t, err, ca.ErrProfileNotFound)
}

func TestRegistry_Resolve_AnyIssuer(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	org := xdb.NewID(1)
	h := f.org(org)
	f.profile(org, xdb.ID(0), ocspProfileDef(ocspProfile))

	_, err := f.registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org, Profile: ocspProfile})
	assert.ErrorIs(t, err, ca.ErrIssuerLabelRequired)

	res, err := f.registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org, Profile: ocspProfile, IssuerLabel: issuerLabel})
	require.NoError(t, err)
	assert.Equal(t, h.issuer.ID.UInt64(), res.Row.ID.UInt64())
	assert.Equal(t, ocspProfile, res.ProfileRow.Label)
	assert.True(t, res.Profile.OCSPNoCheck)

	// an issuer that does not list the profile does not serve it
	f.child(h.platformRoot, caProfile, org, xdb.ID(0), "L3", pb.AuthorityType_Issuing, nil)
	_, err = f.registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org, Profile: ocspProfile, IssuerLabel: "L3"})
	assert.ErrorIs(t, err, ca.ErrProfileNotAllowed)

	// a bound profile refuses another issuer and accepts its own
	_, err = f.registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org, Profile: peerProfile, IssuerLabel: "L3"})
	assert.ErrorIs(t, err, ca.ErrIssuerMismatch)
	res, err = f.registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org, Profile: peerProfile, IssuerLabel: issuerLabel})
	require.NoError(t, err)
	assert.Equal(t, h.issuer.ID.UInt64(), res.Row.ID.UInt64())
}

func TestRegistry_Resolve_Status(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	org := xdb.NewID(1)
	h := f.org(org)

	_, err := f.registry.Resolve(f.ctx, nil)
	assert.EqualError(t, err, "profile is required")
	_, err = f.registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org, Profile: "nope"})
	assert.ErrorIs(t, err, ca.ErrProfileNotFound)
	f.profile(org, xdb.ID(0), peerProfileDef("orphan", "NOPE", "1h"))
	_, err = f.registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org, Profile: "orphan"})
	assert.ErrorIs(t, err, ca.ErrIssuerNotFound)

	// a pending issuer has no certificate
	pending, err := f.keys.NewPendingIssuer(f.ctx, &ca.IssuerRequest{
		OrgID:    org,
		Label:    "P1",
		Type:     pb.AuthorityType_Issuing,
		Subject:  &csr.X509Subject{CommonName: "Pending"},
		Provider: f.prov,
	})
	require.NoError(t, err)
	_, err = f.db.RegisterIssuer(f.ctx, pending, nil)
	require.NoError(t, err)
	f.profile(org, xdb.ID(0), peerProfileDef("pend", "P1", "1h"))
	_, err = f.registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org, Profile: "pend"})
	assert.ErrorIs(t, err, ca.ErrIssuerNotActive)

	// an archived issuer does not sign, but still answers for its certificates
	_, err = f.db.UpdateIssuer(f.ctx, &query.UpdateIssuerRequest{
		ID:     h.issuer.ID.UInt64(),
		OrgID:  org.UInt64(),
		Status: pb.IssuerStatus_Archived,
	})
	require.NoError(t, err)
	f.registry.InvalidateIssuer(h.issuer)
	_, err = f.registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org, Profile: peerProfile})
	assert.ErrorIs(t, err, ca.ErrIssuerNotActive)
	iss, row, err := f.registry.IssuerBySKID(f.ctx, h.issuer.Skid)
	require.NoError(t, err)
	assert.Equal(t, pb.IssuerStatus_Archived, row.Status)
	assert.Equal(t, h.issuer.Skid, iss.SubjectKID())

	// a destroyed issuer answers nothing
	_, err = f.db.UpdateIssuer(f.ctx, &query.UpdateIssuerRequest{
		ID:     h.issuer.ID.UInt64(),
		OrgID:  org.UInt64(),
		Status: pb.IssuerStatus_Destroyed,
	})
	require.NoError(t, err)
	f.registry.InvalidateIssuer(h.issuer)
	_, _, err = f.registry.IssuerBySKID(f.ctx, h.issuer.Skid)
	assert.ErrorIs(t, err, ca.ErrIssuerNotActive)
	_, _, err = f.registry.IssuerBySKID(f.ctx, "nope")
	assert.ErrorIs(t, err, ca.ErrIssuerNotFound)

	// a DB failure is reported, not cached
	f.registry.Purge()
	f.db.Err = errors.New("db down")
	_, err = f.registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org, Profile: peerProfile})
	assert.EqualError(t, err, "unable to find profile: db down")
	_, _, err = f.registry.IssuerBySKID(f.ctx, h.issuer.Skid)
	assert.EqualError(t, err, "unable to find issuer: db down")
	f.db.Err = nil
	f.profile(org, xdb.ID(0), peerProfileDef("late", "L2", "1h"))
	f.db.Err = errors.New("db down")
	_, err = f.registry.FindProfile(f.ctx, org, xdb.ID(0), "late")
	assert.EqualError(t, err, "unable to find profile: db down")
	f.db.Err = nil
	_, err = f.registry.FindIssuer(f.ctx, org, xdb.ID(0), "L2")
	require.NoError(t, err)
}

func TestRegistry_Cache(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	org := xdb.NewID(1)
	project := xdb.NewID(201)
	h := f.org(org)
	f.registry.Purge()
	f.db.ResetCalls()

	res1, err := f.registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org, Profile: peerProfile})
	require.NoError(t, err)
	assert.Equal(t, 1, f.db.Calls("FindProfile"))
	assert.Equal(t, 1, f.db.Calls("FindIssuer"))
	assert.Equal(t, 1, f.registry.Len())

	// the second resolution is served from memory
	res2, err := f.registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org, Profile: peerProfile})
	require.NoError(t, err)
	assert.Equal(t, 1, f.db.Calls("FindProfile"))
	assert.Equal(t, 1, f.db.Calls("FindIssuer"))
	assert.Same(t, res1.Issuer, res2.Issuer)
	assert.Equal(t, res1.ProfileName, res2.ProfileName)

	// a project without its own rows queries both scopes once
	_, err = f.registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org, ProjectID: project, Profile: peerProfile})
	require.NoError(t, err)
	assert.Equal(t, 3, f.db.Calls("FindProfile"))
	assert.Equal(t, 3, f.db.Calls("FindIssuer"))
	_, err = f.registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org, ProjectID: project, Profile: peerProfile})
	require.NoError(t, err)
	assert.Equal(t, 3, f.db.Calls("FindProfile"))
	assert.Equal(t, 3, f.db.Calls("FindIssuer"))
	assert.Equal(t, 1, f.registry.Len(), "one issuer serves both scopes")

	// a replaced profile is served from memory until it is invalidated
	f.profile(org, xdb.ID(0), peerProfileDef(peerProfile, issuerLabel, "48h"))
	res3, err := f.registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org, Profile: peerProfile})
	require.NoError(t, err)
	assert.Equal(t, res1.ProfileName, res3.ProfileName)
	assert.Equal(t, csr.Duration(168*time.Hour), res3.Profile.Expiry)

	f.registry.InvalidateProfile(org, xdb.ID(0), peerProfile)
	res4, err := f.registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org, Profile: peerProfile})
	require.NoError(t, err)
	assert.NotEqual(t, res1.ProfileName, res4.ProfileName, "a new version of the profile")
	assert.Equal(t, csr.Duration(48*time.Hour), res4.Profile.Expiry)
	assert.Same(t, res1.Issuer, res4.Issuer, "the issuer is not rebuilt for a profile change")
	assert.NotNil(t, res1.Issuer.Profile(res1.ProfileName), "the old version stays registered until the issuer is rebuilt")

	// the org-wide invalidation also drops the resolutions of the projects
	res5, err := f.registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org, ProjectID: project, Profile: peerProfile})
	require.NoError(t, err)
	assert.Equal(t, csr.Duration(48*time.Hour), res5.Profile.Expiry)

	// invalidating the issuer rebuilds it
	f.registry.InvalidateIssuer(h.issuer)
	assert.Equal(t, 0, f.registry.Len())
	res6, err := f.registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org, Profile: peerProfile})
	require.NoError(t, err)
	assert.NotSame(t, res1.Issuer, res6.Issuer)
	assert.Equal(t, res1.Issuer.SubjectKID(), res6.Issuer.SubjectKID())
	assert.Nil(t, res6.Issuer.Profile(res1.ProfileName), "the rebuilt issuer has only the current profiles")

	// a newer row rebuilds the issuer, an older one does not replace it
	cfg, err := json.Marshal(&pb.IssuerConfig{AllowedProfiles: []string{ocspProfile, "other"}})
	require.NoError(t, err)
	updated, err := f.db.UpdateIssuer(f.ctx, &query.UpdateIssuerRequest{
		ID:     h.issuer.ID.UInt64(),
		OrgID:  org.UInt64(),
		Config: cfg,
	})
	require.NoError(t, err)
	iss, err := f.registry.Issuer(f.ctx, updated)
	require.NoError(t, err)
	assert.NotSame(t, res6.Issuer, iss)
	iss2, err := f.registry.Issuer(f.ctx, h.issuer)
	require.NoError(t, err)
	assert.Same(t, iss, iss2)
	assert.Equal(t, 1, f.registry.Len())

	// invalidating what is not cached is harmless
	f.registry.InvalidateIssuer(nil)
	f.registry.InvalidateProfile(org, project, "nope")
}

func TestRegistry_TTLAndSize(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	org := xdb.NewID(1)
	h := f.org(org)
	registry := ca.NewRegistry(f.db, f.keys, ca.Options{TTL: 50 * time.Millisecond, Size: 2})

	_, err := registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org, Profile: peerProfile})
	require.NoError(t, err)
	f.db.ResetCalls()
	require.Eventually(t, func() bool {
		_, err := registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org, Profile: peerProfile})
		return err == nil && f.db.Calls("FindProfile") > 0
	}, 5*time.Second, 10*time.Millisecond, "the resolution expires after the TTL")

	// the issuer cache is bounded by its size
	for _, label := range []string{"L3", "L4", "L5"} {
		f.child(h.platformRoot, caProfile, org, xdb.ID(0), label, pb.AuthorityType_Issuing, nil)
		f.profile(org, xdb.ID(0), peerProfileDef("peer-"+label, label, "1h"))
		_, err := registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org, Profile: "peer-" + label})
		require.NoError(t, err)
	}
	assert.LessOrEqual(t, registry.Len(), 2)
}

func TestRegistry_OCSP(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	org := xdb.NewID(1)
	h := f.org(org)
	res, err := f.registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org, Profile: peerProfile})
	require.NoError(t, err)
	leaf, _, err := res.Issuer.Sign(csr.SignRequest{
		Request: newCSR(t, "ocsp.example.com"),
		Profile: res.ProfileName,
	})
	require.NoError(t, err)
	issuerCert, err := certutil.ParseFromPEM([]byte(h.issuer.Pem))
	require.NoError(t, err)

	keyHash := func(hash crypto.Hash) *ocsp.Request {
		der, err := ocsp.CreateRequest(leaf, issuerCert, &ocsp.RequestOptions{Hash: hash})
		require.NoError(t, err)
		req, err := ocsp.ParseRequest(der)
		require.NoError(t, err)
		return req
	}
	sha1Req := keyHash(crypto.SHA1)
	sha256Req := keyHash(crypto.SHA256)

	// a cold registry finds a SHA-1 key hash through the SKID index
	f.registry.Purge()
	f.db.ResetCalls()
	iss, row, err := f.registry.IssuerByKeyHash(f.ctx, crypto.SHA1, sha1Req.IssuerKeyHash)
	require.NoError(t, err)
	assert.Equal(t, h.issuer.ID.UInt64(), row.ID.UInt64())
	assert.Equal(t, h.issuer.Skid, iss.SubjectKID())
	assert.Equal(t, 1, f.db.Calls("GetIssuerBySKID"))

	// a loaded issuer is matched in memory for any hash
	f.db.ResetCalls()
	_, row, err = f.registry.IssuerByKeyHash(f.ctx, crypto.SHA1, sha1Req.IssuerKeyHash)
	require.NoError(t, err)
	assert.Equal(t, h.issuer.ID.UInt64(), row.ID.UInt64())
	_, row, err = f.registry.IssuerByKeyHash(f.ctx, crypto.SHA256, sha256Req.IssuerKeyHash)
	require.NoError(t, err)
	assert.Equal(t, h.issuer.ID.UInt64(), row.ID.UInt64())
	_, row, err = f.registry.IssuerByNameHash(f.ctx, crypto.SHA1, sha1Req.IssuerNameHash)
	require.NoError(t, err)
	assert.Equal(t, h.issuer.ID.UInt64(), row.ID.UInt64())
	_, _, err = f.registry.IssuerBySKID(f.ctx, h.issuer.Skid)
	require.NoError(t, err)
	assert.Equal(t, 0, f.db.Calls("GetIssuerBySKID"))

	// only SHA-1 reaches the DB
	f.registry.Purge()
	_, _, err = f.registry.IssuerByKeyHash(f.ctx, crypto.SHA256, sha256Req.IssuerKeyHash)
	assert.ErrorIs(t, err, ca.ErrIssuerNotFound)
	_, _, err = f.registry.IssuerByNameHash(f.ctx, crypto.SHA1, sha1Req.IssuerNameHash)
	assert.ErrorIs(t, err, ca.ErrIssuerNotFound)
	_, _, err = f.registry.IssuerByKeyHash(f.ctx, crypto.SHA1, []byte("no such key hash!!"))
	assert.ErrorIs(t, err, ca.ErrIssuerNotFound)

	// the resolved issuer signs the status of its certificate
	iss, _, err = f.registry.IssuerByKeyHash(f.ctx, crypto.SHA1, sha1Req.IssuerKeyHash)
	require.NoError(t, err)
	der, err := iss.SignOCSP(&authority.OCSPSignRequest{
		SerialNumber: leaf.SerialNumber,
		Status:       authority.OCSPStatusGood,
		IssuerHash:   crypto.SHA1,
	})
	require.NoError(t, err)
	resp, err := ocsp.ParseResponseForCert(der, leaf, issuerCert)
	require.NoError(t, err)
	assert.Equal(t, ocsp.Good, resp.Status)
}

func TestRegistry_DelegatedOCSP(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	org := xdb.NewID(1)
	f.profile(org, xdb.ID(0), caProfileDef(caProfile, rootLabel))
	root := f.root(org, xdb.ID(0), rootLabel, nil)
	f.profile(org, xdb.ID(0), ocspProfileDef(ocspProfile))
	issuer := f.child(root, caProfile, org, xdb.ID(0), issuerLabel, pb.AuthorityType_Issuing, &pb.IssuerConfig{
		AllowedProfiles:      []string{ocspProfile},
		DelegatedOcspProfile: ocspProfile,
		OcspExpiry:           "1h",
		CrlExpiry:            "48h",
		CrlRenewal:           "12h",
		OcspURL:              "http://cis.example.com/v1/ocsp/${ISSUER_ID}",
	})
	f.profile(org, xdb.ID(0), peerProfileDef(peerProfile, issuerLabel, "1h"))

	res, err := f.registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org, Profile: peerProfile})
	require.NoError(t, err)
	assert.Equal(t, time.Hour, res.Issuer.OcspExpiry())
	assert.Equal(t, 48*time.Hour, res.Issuer.CrlExpiry())
	assert.Equal(t, 12*time.Hour, res.Issuer.CrlRenewal())
	assert.Equal(t, "http://cis.example.com/v1/ocsp/"+issuer.Skid, res.Issuer.OcspURL())
	assert.NotNil(t, res.Issuer.Profile(ocspProfile), "the delegated profile is registered under its label")

	// the delegated responder signs with a responder certificate the issuer issued
	der, err := res.Issuer.SignOCSP(&authority.OCSPSignRequest{
		SerialNumber: big.NewInt(1),
		Status:       authority.OCSPStatusGood,
		IssuerHash:   crypto.SHA1,
	})
	require.NoError(t, err)
	issuerCert, err := certutil.ParseFromPEM([]byte(issuer.Pem))
	require.NoError(t, err)
	resp, err := ocsp.ParseResponse(der, issuerCert)
	require.NoError(t, err)
	require.NotNil(t, resp.Certificate, "a delegated responder certificate")
	assert.NotEqual(t, issuerCert.SerialNumber, resp.Certificate.SerialNumber)
	assert.Contains(t, resp.Certificate.ExtKeyUsage, x509.ExtKeyUsageOCSPSigning)

	// an issuer whose delegated profile is not allowed for it does not load
	f.child(root, caProfile, org, xdb.ID(0), "L3", pb.AuthorityType_Issuing, &pb.IssuerConfig{
		DelegatedOcspProfile: ocspProfile,
	})
	f.profile(org, xdb.ID(0), peerProfileDef("p3", "L3", "1h"))
	_, err = f.registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org, Profile: "p3"})
	assert.ErrorContains(t, err, `delegated OCSP profile "ocsp" is not bound to issuer`)

	// nor one whose delegated profile does not exist
	f.child(root, caProfile, org, xdb.ID(0), "L4", pb.AuthorityType_Issuing, &pb.IssuerConfig{
		AllowedProfiles:      []string{"nope"},
		DelegatedOcspProfile: "nope",
	})
	f.profile(org, xdb.ID(0), peerProfileDef("p4", "L4", "1h"))
	_, err = f.registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org, Profile: "p4"})
	assert.NotErrorIs(t, err, ca.ErrProfileNotFound, "the profile of the request exists: the issuer does not load")
	assert.ErrorContains(t, err, `delegated OCSP profile "nope" of issuer`)
	assert.ErrorContains(t, err, "is not found")

	// an invalid stored setting does not load either
	f.child(root, caProfile, org, xdb.ID(0), "L5", pb.AuthorityType_Issuing, &pb.IssuerConfig{
		OcspExpiry: "soon",
	})
	f.profile(org, xdb.ID(0), peerProfileDef("p5", "L5", "1h"))
	_, err = f.registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org, Profile: "p5"})
	assert.ErrorContains(t, err, `invalid OcspExpiry: "soon" is not a duration`)
}

func TestRegistry_Concurrent(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	org := xdb.NewID(1)
	h := f.org(org)
	f.registry.Purge()

	const workers = 32
	results := make([]*authority.Issuer, workers)
	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := f.registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org, Profile: peerProfile})
			if assert.NoError(t, err) {
				results[i] = res.Issuer
			}
		}()
	}
	wg.Wait()
	for i := range workers {
		assert.Same(t, results[0], results[i], "one build serves every waiter")
	}
	assert.Equal(t, 1, f.registry.Len())

	// resolutions, invalidations and signing run concurrently
	wg = sync.WaitGroup{}
	for i := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := f.registry.Resolve(f.ctx, &ca.ResolveRequest{OrgID: org, Profile: peerProfile})
			if !assert.NoError(t, err) {
				return
			}
			_, _, err = res.Issuer.Sign(csr.SignRequest{
				Request: newCSR(t, "c.example.com"),
				Profile: res.ProfileName,
			})
			assert.NoError(t, err)
			if i%4 == 0 {
				f.registry.InvalidateIssuer(h.issuer)
			}
			if i%4 == 1 {
				f.registry.InvalidateProfile(org, xdb.ID(0), peerProfile)
			}
		}()
	}
	wg.Wait()
}
