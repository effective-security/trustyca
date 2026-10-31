package ca_test

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/ca"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xpki/authority"
	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/csr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"
)

// parseCRL parses the PEM of a stored CRL and verifies its signature
// against the issuer row
func parseCRL(t *testing.T, crl *model.Crl, issuer *model.Issuer) *x509.RevocationList {
	t.Helper()
	block, _ := pem.Decode([]byte(crl.Pem))
	require.NotNil(t, block)
	assert.Equal(t, ca.CrlPEMType, block.Type)
	list, err := x509.ParseRevocationList(block.Bytes)
	require.NoError(t, err)
	cert, err := certutil.ParseFromPEM([]byte(issuer.Pem))
	require.NoError(t, err)
	require.NoError(t, list.CheckSignatureFrom(cert))
	assert.Equal(t, cert.SubjectKeyId, list.AuthorityKeyId)
	return list
}

// serials returns the serial numbers of the CRL entries with their reasons
func serials(list *x509.RevocationList) map[string]int {
	res := map[string]int{}
	for _, e := range list.RevokedCertificateEntries {
		res[e.SerialNumber.String()] = e.ReasonCode
	}
	return res
}

func TestCrlDue(t *testing.T) {
	t.Parallel()
	now := time.Now()
	renewal := 12 * time.Hour
	crl := func(nextUpdate time.Time) *model.Crl {
		return &model.Crl{NextUpdate: xdb.UTC(nextUpdate)}
	}
	assert.True(t, ca.CrlDue(nil, renewal, now), "no CRL")
	assert.True(t, ca.CrlDue(crl(now.Add(-time.Hour)), renewal, now), "expired")
	assert.True(t, ca.CrlDue(crl(now.Add(renewal)), renewal, now), "at the renewal boundary")
	assert.True(t, ca.CrlDue(crl(now.Add(renewal-time.Minute)), renewal, now), "within the renewal period")
	assert.False(t, ca.CrlDue(crl(now.Add(renewal+time.Minute)), renewal, now), "not yet")
	assert.False(t, ca.CrlDue(crl(now.Add(time.Minute)), 0, now), "no renewal period: due at the next update")
}

func TestCrlPublisher_PublishCrl(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	org := xdb.NewID(1)
	h := f.org(org)
	pub := ca.NewCrlPublisher(f.db, f.registry)
	issuer := h.issuer
	start := time.Now().Truncate(time.Second)

	// the first CRL of an issuer: number 1, no entries, the default
	// validity of the issuer settings
	crl, published, err := pub.PublishCrl(f.ctx, issuer, false)
	require.NoError(t, err)
	require.True(t, published)
	assert.EqualValues(t, 1, crl.CrlNumber)
	assert.Equal(t, issuer.Skid, crl.Ikid)
	assert.Equal(t, issuer.ID.UInt64(), crl.IssuerID.UInt64())
	assert.Equal(t, org.UInt64(), crl.OrgID.UInt64())
	assert.Equal(t, issuer.Subject, crl.Issuer)
	assert.False(t, crl.ThisUpdate.UTC().Before(start))
	assert.Equal(t, authority.DefaultCRLExpiry, crl.NextUpdate.UTC().Sub(crl.ThisUpdate.UTC()))
	list := parseCRL(t, crl, issuer)
	assert.Empty(t, list.RevokedCertificateEntries)
	assert.EqualValues(t, 1, list.Number.Int64())
	assert.Equal(t, crl.ThisUpdate.UTC(), list.ThisUpdate)
	assert.Equal(t, crl.NextUpdate.UTC(), list.NextUpdate)
	row, err := f.db.GetIssuer(f.ctx, issuer.ID.UInt64())
	require.NoError(t, err)
	assert.EqualValues(t, 1, row.CrlNumber, "the issuer records the number")

	// not due: the current CRL is returned
	again, published, err := pub.PublishCrl(f.ctx, row, false)
	require.NoError(t, err)
	assert.False(t, published)
	assert.Equal(t, crl.ID.UInt64(), again.ID.UInt64())
	assert.EqualValues(t, 1, again.CrlNumber)

	// forced: the next number
	crl2, published, err := pub.PublishCrl(f.ctx, row, true)
	require.NoError(t, err)
	assert.True(t, published)
	assert.EqualValues(t, 2, crl2.CrlNumber)
	assert.Equal(t, crl.ID.UInt64(), crl2.ID.UInt64(), "the current CRL is replaced")
	assert.EqualValues(t, 2, parseCRL(t, crl2, issuer).Number.Int64())

	// due by the renewal period
	f.db.setCrlNextUpdate(issuer.Skid, time.Now().Add(authority.DefaultCRLRenewal-time.Minute))
	row, err = f.db.GetIssuer(f.ctx, issuer.ID.UInt64())
	require.NoError(t, err)
	crl3, published, err := pub.PublishCrl(f.ctx, row, false)
	require.NoError(t, err)
	assert.True(t, published)
	assert.EqualValues(t, 3, crl3.CrlNumber)

	// the entries: the revocations of the certificates that are still
	// valid, with their reasons, across pages; an expired one is left out
	now := time.Now()
	f.db.revoke(issuer, "1001", now.Add(time.Hour), now.Add(-time.Hour), pb.ReasonCode_KeyCompromise)
	f.db.revoke(issuer, "1002", now.Add(time.Hour), now.Add(-time.Minute), pb.ReasonCode_Unspecified)
	f.db.revoke(issuer, "1003", now.Add(-time.Minute), now.Add(-time.Hour), pb.ReasonCode_CessationOfOperation)
	f.db.revoke(h.platformRoot, "1004", now.Add(time.Hour), now.Add(-time.Hour), pb.ReasonCode_Superseded)
	for i := range 1100 {
		f.db.revoke(issuer, fmt.Sprintf("%d", 2000+i), now.Add(time.Hour), now.Add(-time.Hour), pb.ReasonCode_CertificateHold)
	}
	f.db.ResetCalls()
	row, err = f.db.GetIssuer(f.ctx, issuer.ID.UInt64())
	require.NoError(t, err)
	crl4, published, err := pub.PublishCrl(f.ctx, row, true)
	require.NoError(t, err)
	assert.True(t, published)
	assert.EqualValues(t, 4, crl4.CrlNumber)
	assert.Equal(t, 2, f.db.Calls("ListRevoked"), "two pages of entries")
	list = parseCRL(t, crl4, issuer)
	entries := serials(list)
	assert.Len(t, entries, 1102)
	assert.Equal(t, ocsp.KeyCompromise, entries["1001"])
	assert.Equal(t, ocsp.Unspecified, entries["1002"])
	assert.Equal(t, ocsp.CertificateHold, entries["2000"])
	assert.NotContains(t, entries, "1003", "expired")
	assert.NotContains(t, entries, "1004", "another issuer's")
	for _, e := range list.RevokedCertificateEntries {
		if e.SerialNumber.Cmp(big.NewInt(1001)) == 0 {
			assert.Equal(t, now.Add(-time.Hour).Truncate(time.Second).UTC(), e.RevocationTime)
		}
	}

	// the root's CRL carries the root's revocation only
	rootCrl, published, err := pub.PublishCrl(f.ctx, h.platformRoot, false)
	require.NoError(t, err)
	assert.True(t, published)
	assert.Equal(t, map[string]int{"1004": ocsp.Superseded}, serials(parseCRL(t, rootCrl, h.platformRoot)))

	// the validity is capped at the expiry of the issuer certificate
	f.profile(org, xdb.ID(0), &pb.CertProfile{
		Label:       "SHORT",
		IssuerLabel: rootLabel,
		Expiry:      "2h",
		Backdate:    "30m",
		Usages:      []string{"cert sign", "crl sign"},
		CAConstraint: &pb.CAConstraint{
			IsCA:       true,
			MaxPathLen: 0,
		},
	})
	soon := f.child(h.platformRoot, "SHORT", org, xdb.ID(0), "SOON", pb.AuthorityType_Issuing, &pb.IssuerConfig{
		CrlExpiry: "720h",
	})
	soonCrl, published, err := pub.PublishCrl(f.ctx, soon, false)
	require.NoError(t, err)
	assert.True(t, published)
	soonCert, err := certutil.ParseFromPEM([]byte(soon.Pem))
	require.NoError(t, err)
	assert.Equal(t, soonCert.NotAfter.UTC(), soonCrl.NextUpdate.UTC())
}

func TestCrlPublisher_PublishCrl_Stale(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	org := xdb.NewID(1)
	h := f.org(org)
	pub := ca.NewCrlPublisher(f.db, f.registry)

	// another publisher stores number 1 first: the CRL is signed again
	// with number 2 when forced
	f.db.Stale = 1
	crl, published, err := pub.PublishCrl(f.ctx, h.issuer, true)
	require.NoError(t, err)
	assert.True(t, published)
	assert.EqualValues(t, 2, crl.CrlNumber)
	assert.NotEqual(t, "other publisher", crl.Pem)
	row, err := f.db.GetIssuer(f.ctx, h.issuer.ID.UInt64())
	require.NoError(t, err)
	assert.EqualValues(t, 2, row.CrlNumber)

	// the other publisher's CRL is fresh: not forced, it is kept
	f.db.Stale = 1
	f.db.setCrlNextUpdate(h.issuer.Skid, time.Now().Add(time.Minute))
	crl, published, err = pub.PublishCrl(f.ctx, row, false)
	require.NoError(t, err)
	assert.False(t, published)
	assert.EqualValues(t, 3, crl.CrlNumber)
	assert.Equal(t, "other publisher", crl.Pem)

	// a number that is stale again after the retry is an error
	f.db.Stale = 2
	_, _, err = pub.PublishCrl(f.ctx, row, true)
	assert.ErrorContains(t, err, "crl number is not greater than the issuer's crl number")
	assert.ErrorContains(t, err, "unable to publish CRL of issuer")
	assert.Zero(t, f.db.Stale, "two attempts")
	row, err = f.db.GetIssuer(f.ctx, h.issuer.ID.UInt64())
	require.NoError(t, err)
	assert.EqualValues(t, 4, row.CrlNumber, "the numbers of the other publisher: 3 on the first attempt, 4 on the retry")
}

func TestCrlPublisher_PublishCrl_Errors(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	org := xdb.NewID(1)
	h := f.org(org)
	pub := ca.NewCrlPublisher(f.db, f.registry)

	pending, err := f.keys.NewPendingIssuer(f.ctx, &ca.IssuerRequest{
		OrgID:    org,
		Label:    "PENDING",
		Type:     pb.AuthorityType_Issuing,
		Subject:  &csr.X509Subject{CommonName: "Pending CA"},
		Provider: f.prov,
	})
	require.NoError(t, err)
	pending, err = f.db.RegisterIssuer(f.ctx, pending, nil)
	require.NoError(t, err)
	_, _, err = pub.PublishCrl(f.ctx, pending, true)
	assert.ErrorIs(t, err, ca.ErrIssuerNotActive)
	destroyed := *h.issuer
	destroyed.Status = pb.IssuerStatus_Destroyed
	_, _, err = pub.PublishCrl(f.ctx, &destroyed, true)
	assert.ErrorIs(t, err, ca.ErrIssuerNotActive)

	expired := *h.issuer
	expired.NotAfter = xdb.UTC(time.Now().Add(-time.Minute))
	_, _, err = pub.PublishCrl(f.ctx, &expired, true)
	assert.ErrorIs(t, err, ca.ErrIssuerExpired)

	// a CA whose certificate cannot sign CRLs
	f.profile(org, xdb.ID(0), &pb.CertProfile{
		Label:       "NOCRL",
		IssuerLabel: rootLabel,
		Expiry:      "8760h",
		Backdate:    "30m",
		Usages:      []string{"cert sign"},
		CAConstraint: &pb.CAConstraint{
			IsCA:       true,
			MaxPathLen: 0,
		},
	})
	noCrl := f.child(h.platformRoot, "NOCRL", org, xdb.ID(0), "NOCRL", pb.AuthorityType_Issuing, nil)
	_, _, err = pub.PublishCrl(f.ctx, noCrl, true)
	assert.ErrorContains(t, err, "unable to sign CRL of issuer")
	assert.ErrorContains(t, err, "crlSign")

	// DB failures
	f.db.Err = errors.New("db down")
	_, _, err = pub.PublishCrl(f.ctx, h.issuer, true)
	assert.ErrorContains(t, err, "db down")
	f.db.Err = nil
	f.registry.Purge()
	f.db.revoke(h.issuer, "bad", time.Now().Add(time.Hour), time.Now(), pb.ReasonCode_Unspecified)
	_, _, err = pub.PublishCrl(f.ctx, h.issuer, true)
	assert.ErrorContains(t, err, `invalid serial number "bad" of revoked certificate`)
}

func TestCrlPublisher_PublishCrls(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	org1 := xdb.NewID(1)
	org2 := xdb.NewID(2)
	h1 := f.org(org1)
	h2 := f.org(org2)
	pub := ca.NewCrlPublisher(f.db, f.registry)

	// the issuers of a project, and of every status
	project := xdb.NewID(201)
	projectIssuer := f.child(h1.platformRoot, caProfile, org1, project, "PRJ", pb.AuthorityType_Issuing, nil)
	archived := f.child(h1.platformRoot, caProfile, org1, xdb.ID(0), "ARCHIVED", pb.AuthorityType_Issuing, nil)
	f.db.setIssuerStatus(archived.ID, pb.IssuerStatus_Archived)
	destroyed := f.child(h1.platformRoot, caProfile, org1, xdb.ID(0), "DESTROYED", pb.AuthorityType_Issuing, nil)
	f.db.setIssuerStatus(destroyed.ID, pb.IssuerStatus_Destroyed)
	expired := f.child(h1.platformRoot, caProfile, org1, xdb.ID(0), "EXPIRED", pb.AuthorityType_Issuing, nil)
	f.db.setIssuerNotAfter(expired.ID, time.Now().Add(-time.Minute))
	pending, err := f.keys.NewPendingIssuer(f.ctx, &ca.IssuerRequest{
		OrgID:    org1,
		Label:    "PENDING",
		Type:     pb.AuthorityType_Issuing,
		Subject:  &csr.X509Subject{CommonName: "Pending CA"},
		Provider: f.prov,
	})
	require.NoError(t, err)
	_, err = f.db.RegisterIssuer(f.ctx, pending, nil)
	require.NoError(t, err)

	ikids := func(res *ca.PublishCrlsResult) []string {
		var ids []string
		for _, crl := range res.Crls {
			ids = append(ids, crl.Ikid)
		}
		return ids
	}

	// every org: the Active and Archived issuers whose certificate is
	// valid, Active first, newest first within a status; the current CRLs
	// are read once per page of issuers
	f.db.ResetCalls()
	res, err := pub.PublishCrls(f.ctx, &ca.PublishCrlsRequest{AllOrgs: true})
	require.NoError(t, err)
	assert.Equal(t, []string{projectIssuer.Skid, h2.issuer.Skid, h2.platformRoot.Skid, h1.issuer.Skid, h1.platformRoot.Skid, archived.Skid}, ikids(res))
	assert.Equal(t, 1, res.Skipped, "the expired issuer")
	assert.Zero(t, res.Failed)
	for _, crl := range res.Crls {
		assert.EqualValues(t, 1, crl.CrlNumber)
	}
	assert.Equal(t, 2, f.db.Calls("GetCrls"), "a page of Active and a page of Archived issuers")
	assert.Zero(t, f.db.Calls("GetCrl"), "no lookup per issuer")

	// nothing is due now: the issuers are not loaded
	f.registry.Purge()
	f.db.ResetCalls()
	res, err = pub.PublishCrls(f.ctx, &ca.PublishCrlsRequest{AllOrgs: true})
	require.NoError(t, err)
	assert.Empty(t, res.Crls)
	assert.Equal(t, 7, res.Skipped)
	assert.Zero(t, res.Failed)
	assert.Zero(t, f.registry.Len(), "no signer is loaded when nothing is due")
	assert.Equal(t, 2, f.db.Calls("GetCrls"))
	assert.Zero(t, f.db.Calls("GetCrl"))

	// the scope of a tenant request: the org, a project, the visible
	// projects
	res, err = pub.PublishCrls(f.ctx, &ca.PublishCrlsRequest{OrgID: org2, Force: true})
	require.NoError(t, err)
	assert.Equal(t, []string{h2.issuer.Skid, h2.platformRoot.Skid}, ikids(res))
	res, err = pub.PublishCrls(f.ctx, &ca.PublishCrlsRequest{OrgID: org1, ProjectID: project, Force: true})
	require.NoError(t, err)
	assert.Equal(t, []string{projectIssuer.Skid}, ikids(res))
	res, err = pub.PublishCrls(f.ctx, &ca.PublishCrlsRequest{OrgID: org1, ProjectIDs: []uint64{}, Force: true})
	require.NoError(t, err)
	assert.Equal(t, []string{h1.issuer.Skid, h1.platformRoot.Skid, archived.Skid}, ikids(res), "the org-wide issuers only")
	assert.Equal(t, 1, res.Skipped)
	_, err = pub.PublishCrls(f.ctx, &ca.PublishCrlsRequest{})
	assert.ErrorContains(t, err, "org scope is required")

	// a failure does not stop the run: the issuer without the CRL signing
	// usage fails; the due CRL of the issuing CA is taken by another
	// publisher first, whose fresh CRL is kept
	f.profile(org1, xdb.ID(0), &pb.CertProfile{
		Label:       "NOCRL",
		IssuerLabel: rootLabel,
		Expiry:      "8760h",
		Backdate:    "30m",
		Usages:      []string{"cert sign"},
		CAConstraint: &pb.CAConstraint{
			IsCA:       true,
			MaxPathLen: 0,
		},
	})
	noCrl := f.child(h1.platformRoot, "NOCRL", org1, xdb.ID(0), "NOCRL", pb.AuthorityType_Issuing, nil)
	f.db.setCrlNextUpdate(h1.issuer.Skid, time.Now())
	f.db.Stale = 1
	res, err = pub.PublishCrls(f.ctx, &ca.PublishCrlsRequest{OrgID: org1, ProjectIDs: []uint64{}})
	require.NoError(t, err)
	assert.Equal(t, 1, res.Failed)
	assert.Empty(t, ikids(res))
	assert.Equal(t, 4, res.Skipped, "the root, the archived and the expired issuers, and the one another publisher served")
	assert.Zero(t, f.db.Stale)
	other, err := f.db.GetCrl(f.ctx, h1.issuer.Skid)
	require.NoError(t, err)
	assert.Equal(t, "other publisher", other.Pem)
	assert.EqualValues(t, 3, other.CrlNumber)
	_, _, err = pub.PublishCrl(f.ctx, noCrl, true)
	assert.ErrorContains(t, err, "crlSign")

	f.db.Err = errors.New("db down")
	_, err = pub.PublishCrls(f.ctx, &ca.PublishCrlsRequest{AllOrgs: true})
	assert.EqualError(t, err, "unable to list issuers: db down")
	f.db.Err = nil
	f.db.ErrOn = "GetCrls"
	_, err = pub.PublishCrls(f.ctx, &ca.PublishCrlsRequest{AllOrgs: true})
	assert.EqualError(t, err, "unable to read current CRLs: GetCrls failed")
}

// TestCountCrls covers the CRL counts of the tenant summary: the issuers
// that publish CRLs by the state of their current CRL at a time, from the
// projected states the DB lists
func TestCountCrls(t *testing.T) {
	t.Parallel()
	now := time.Now()
	valid := now.Add(365 * 24 * time.Hour)
	var nextID uint64
	state := func(label string, notAfter, nextUpdate time.Time, cfg *pb.IssuerConfig) *model.CrlState {
		nextID++
		m := &model.CrlState{
			ID:       xdb.NewID(nextID),
			Label:    label,
			Skid:     label,
			NotAfter: xdb.UTC(notAfter),
		}
		if !nextUpdate.IsZero() {
			m.NextUpdate = xdb.UTC(nextUpdate)
		}
		if cfg != nil {
			var err error
			m.Config, err = model.MarshalJSONValue(cfg)
			require.NoError(t, err)
		}
		return m
	}

	states := []*model.CrlState{
		state("missing", valid, time.Time{}, nil),
		state("current", valid, now.Add(48*time.Hour), nil),
		// the default renewal period is 12 hours; a custom one of a day
		state("due", valid, now.Add(time.Hour), nil),
		state("due-custom", valid, now.Add(20*time.Hour), &pb.IssuerConfig{CrlRenewal: "24h"}),
		state("overdue", valid, now.Add(-time.Minute), nil),
		// an expired issuer certificate publishes no CRL
		state("expired", now.Add(-time.Minute), now.Add(48*time.Hour), nil),
	}
	res, err := ca.CountCrls(states, now)
	require.NoError(t, err)
	assert.Equal(t, &ca.CrlCounts{Issuers: 5, Current: 1, Due: 2, Overdue: 1, Missing: 1}, res)

	res, err = ca.CountCrls(nil, now)
	require.NoError(t, err)
	assert.Equal(t, &ca.CrlCounts{}, res)

	// the settings are read for a CRL that is neither missing nor overdue
	bad := &pb.IssuerConfig{CrlRenewal: "x"}
	_, err = ca.CountCrls([]*model.CrlState{state("bad", valid, now.Add(48*time.Hour), bad)}, now)
	assert.ErrorContains(t, err, "invalid config of issuer")
	res, err = ca.CountCrls([]*model.CrlState{
		state("bad-missing", valid, time.Time{}, bad),
		state("bad-overdue", valid, now.Add(-time.Minute), bad),
	}, now)
	require.NoError(t, err)
	assert.Equal(t, &ca.CrlCounts{Issuers: 2, Overdue: 1, Missing: 1}, res)
}
