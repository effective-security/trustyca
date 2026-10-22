package ca_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/effective-security/trustyca/internal/ca"
	"github.com/effective-security/trustyca/internal/ca/pbconv"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xpki/authority"
	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/csr"
	"github.com/stretchr/testify/require"
)

// benchOrgs is the number of orgs the resolution benchmarks register, each
// with an issuer of the same label and a peer profile
const benchOrgs = 16

// benchFixture registers benchOrgs orgs and returns the fixture and the CSR
// the benchmarks sign
func benchFixture(b *testing.B) (*fixture, string) {
	b.Helper()
	f := newFixture(b)
	for i := range benchOrgs {
		f.org(xdb.NewID(uint64(i + 1)))
	}
	return f, newCSR(b, "bench.example.com")
}

// BenchmarkRegistry_Resolve measures the warm path of the registry: the
// resolution of a profile and its issuer from memory
func BenchmarkRegistry_Resolve(b *testing.B) {
	f, _ := benchFixture(b)
	req := &ca.ResolveRequest{OrgID: xdb.NewID(1), Profile: peerProfile}
	_, err := f.registry.Resolve(f.ctx, req)
	require.NoError(b, err)
	b.ReportAllocs()
	for b.Loop() {
		_, err := f.registry.Resolve(f.ctx, req)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkRegistry_Resolve_Rotating measures the warm path across orgs, so
// every resolution is for another cached issuer
func BenchmarkRegistry_Resolve_Rotating(b *testing.B) {
	f, _ := benchFixture(b)
	reqs := make([]*ca.ResolveRequest, benchOrgs)
	for i := range benchOrgs {
		reqs[i] = &ca.ResolveRequest{OrgID: xdb.NewID(uint64(i + 1)), Profile: peerProfile}
		_, err := f.registry.Resolve(f.ctx, reqs[i])
		require.NoError(b, err)
	}
	b.ReportAllocs()
	i := 0
	for b.Loop() {
		_, err := f.registry.Resolve(f.ctx, reqs[i%benchOrgs])
		if err != nil {
			b.Fatal(err)
		}
		i++
	}
}

// BenchmarkRegistry_Resolve_Cold measures the cold path: the DB lookups,
// the key load and the construction of the issuer. The DB is in memory, so
// the result is the cost without the network round trips.
func BenchmarkRegistry_Resolve_Cold(b *testing.B) {
	f, _ := benchFixture(b)
	req := &ca.ResolveRequest{OrgID: xdb.NewID(1), Profile: peerProfile}
	b.ReportAllocs()
	for b.Loop() {
		f.registry.Purge()
		_, err := f.registry.Resolve(f.ctx, req)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkRegistry_Sign measures the warm path with the signature: what a
// SignCertificate costs without the DB registration
func BenchmarkRegistry_Sign(b *testing.B) {
	f, csrPEM := benchFixture(b)
	req := &ca.ResolveRequest{OrgID: xdb.NewID(1), Profile: peerProfile}
	b.ReportAllocs()
	for b.Loop() {
		res, err := f.registry.Resolve(f.ctx, req)
		if err != nil {
			b.Fatal(err)
		}
		_, _, err = res.Issuer.Sign(csr.SignRequest{
			Request: csrPEM,
			Profile: res.ProfileName,
		})
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkAuthority_Sign is the baseline of a single authority.Authority
// that registers every issuer under an org-prefixed label (option A): the
// lookup by profile, then the signature
func BenchmarkAuthority_Sign(b *testing.B) {
	f, csrPEM := benchFixture(b)
	auth, err := authority.NewAuthority(&authority.Config{Authority: &authority.CAConfig{}}, nil)
	require.NoError(b, err)
	profile, err := pbconv.ProfileFromPb(peerProfileDef(peerProfile, issuerLabel, "168h"))
	require.NoError(b, err)
	for i := range benchOrgs {
		orgID := xdb.NewID(uint64(i + 1))
		row, err := f.db.FindIssuer(f.ctx, orgID.UInt64(), 0, issuerLabel)
		require.NoError(b, err)
		signer, err := f.keys.Signer(f.ctx, row)
		require.NoError(b, err)
		label := fmt.Sprintf("%d_%s", orgID.UInt64(), issuerLabel)
		p := profile.Copy()
		p.IssuerLabel = label
		issuer, err := authority.CreateIssuer(&authority.IssuerConfig{
			Label: label,
			AIA:   &authority.AIAConfig{OCSPExpiry: time.Hour},
			Profiles: map[string]*authority.CertProfile{
				fmt.Sprintf("%d_%s", orgID.UInt64(), peerProfile): p,
			},
		}, []byte(row.Pem), []byte(row.ChainPem), []byte(row.RootPem), signer)
		require.NoError(b, err)
		require.NoError(b, auth.AddIssuer(issuer))
	}
	profileLabel := fmt.Sprintf("%d_%s", 1, peerProfile)
	b.ReportAllocs()
	for b.Loop() {
		issuer, err := auth.GetIssuerByProfile(profileLabel)
		if err != nil {
			b.Fatal(err)
		}
		_, _, err = issuer.Sign(csr.SignRequest{
			Request: csrPEM,
			Profile: profileLabel,
		})
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkAuthority_GetIssuerByProfile is the lookup of option A alone
func BenchmarkAuthority_GetIssuerByProfile(b *testing.B) {
	auth, err := authority.NewAuthority(&authority.Config{Authority: &authority.CAConfig{}}, nil)
	require.NoError(b, err)
	f := newFixture(b)
	h := f.org(xdb.NewID(1))
	signer, err := f.keys.Signer(f.ctx, h.issuer)
	require.NoError(b, err)
	profile, err := pbconv.ProfileFromPb(peerProfileDef(peerProfile, "1_L2", "168h"))
	require.NoError(b, err)
	issuer, err := authority.CreateIssuer(&authority.IssuerConfig{
		Label:    "1_L2",
		AIA:      &authority.AIAConfig{},
		Profiles: map[string]*authority.CertProfile{"1_peer": profile},
	}, []byte(h.issuer.Pem), []byte(h.issuer.ChainPem), []byte(h.issuer.RootPem), signer)
	require.NoError(b, err)
	require.NoError(b, auth.AddIssuer(issuer))
	require.NotEmpty(b, certutil.GetSubjectKeyID(issuer.Bundle().Cert))
	b.ReportAllocs()
	for b.Loop() {
		_, err := auth.GetIssuerByProfile("1_peer")
		if err != nil {
			b.Fatal(err)
		}
	}
}
