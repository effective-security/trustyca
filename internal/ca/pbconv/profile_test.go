package pbconv_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/ca/pbconv"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xpki/authority"
	"github.com/effective-security/xpki/csr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// fullProfile is a definition with every field the conversion handles
func fullProfile() *pb.CertProfile {
	return &pb.CertProfile{
		ID:          "5",
		OrgID:       "1",
		Label:       "server",
		IssuerLabel: "L2",
		Description: "server profile",
		Usages:      []string{"signing", "key encipherment", "server auth"},
		CAConstraint: &pb.CAConstraint{
			IsCA:       false,
			MaxPathLen: 0,
		},
		OcspNoCheck:       true,
		Expiry:            "168h",
		Backdate:          "30m",
		Extensions:        []*pb.X509Extension{{ID: "2.5.29.31", Critical: false, Value: "hex:0500"}},
		AllowedExtensions: []string{"1.3.6.1.5.5.7.1.1", "2.5.29.17"},
		AllowedNames:      "^[a-z.]+$",
		AllowedDns:        `^.*\.example\.com$`,
		AllowedEmail:      "^.*@example.com$",
		AllowedUri:        "^spiffe://example/.*$",
		AllowedFields: &pb.CSRAllowedFields{
			Subject: true,
			Dns:     true,
			Ip:      false,
			Email:   false,
			Uri:     true,
		},
		Policies: []*pb.CertificatePolicy{{
			ID: "2.16.840.1.114569.1.1.3",
			Qualifiers: []*pb.CertificatePolicyQualifier{
				{Type: csr.CpsQualifierType, Value: "https://example.com/cps"},
			},
		}},
		PoliciesCritical: true,
		AllowedRoles:     []string{"ra"},
		DeniedRoles:      []string{"guest"},
		Status:           pb.ItemStatus_Active,
	}
}

func TestProfileFromPb(t *testing.T) {
	t.Parallel()
	p, err := pbconv.ProfileFromPb(fullProfile())
	require.NoError(t, err)
	assert.Equal(t, "L2", p.IssuerLabel)
	assert.Equal(t, "server profile", p.Description)
	assert.Equal(t, []string{"signing", "key encipherment", "server auth"}, p.Usage)
	assert.False(t, p.CAConstraint.IsCA)
	assert.True(t, p.OCSPNoCheck)
	assert.Equal(t, csr.Duration(168*time.Hour), p.Expiry)
	assert.Equal(t, csr.Duration(30*time.Minute), p.Backdate)
	require.Len(t, p.Extensions, 1)
	assert.Equal(t, "2.5.29.31", p.Extensions[0].ID.String())
	assert.Equal(t, "hex:0500", p.Extensions[0].Value)
	assert.Equal(t, []string{"1.3.6.1.5.5.7.1.1", "2.5.29.17"}, p.AllowedExtensionsStrings())
	assert.Equal(t, "^[a-z.]+$", p.AllowedNames)
	require.NotNil(t, p.AllowedNamesRegex, "Validate compiles the patterns")
	require.NotNil(t, p.AllowedDNSRegex)
	require.NotNil(t, p.AllowedEmailRegex)
	require.NotNil(t, p.AllowedURIRegex)
	assert.True(t, p.AllowedDNSRegex.MatchString("a.example.com"))
	require.NotNil(t, p.AllowedCSRFields)
	assert.Equal(t, &csr.AllowedFields{Subject: true, DNSNames: true, URIs: true}, p.AllowedCSRFields)
	require.Len(t, p.Policies, 1)
	assert.Equal(t, "2.16.840.1.114569.1.1.3", p.Policies[0].ID.String())
	assert.Equal(t, []csr.CertificatePolicyQualifier{{Type: csr.CpsQualifierType, Value: "https://example.com/cps"}}, p.Policies[0].Qualifiers)
	assert.True(t, p.PoliciesCritical)
	assert.Equal(t, []string{"ra"}, p.AllowedRoles)
	assert.Equal(t, []string{"guest"}, p.DeniedRoles)

	// a CA profile
	cap, err := pbconv.ProfileFromPb(caProfileDef("CA", "ROOT"))
	require.NoError(t, err)
	assert.True(t, cap.CAConstraint.IsCA)
	assert.Equal(t, 0, cap.CAConstraint.MaxPathLen)
	assert.Nil(t, cap.AllowedCSRFields, "absent means every field may be copied")

	tcases := []struct {
		name string
		mod  func(p *pb.CertProfile)
		err  string
	}{
		{name: "nil", mod: nil, err: "invalid profile: required"},
		{name: "no expiry", mod: func(p *pb.CertProfile) { p.Expiry = "" }, err: "invalid profile: no expiry set"},
		{name: "bad expiry", mod: func(p *pb.CertProfile) { p.Expiry = "1 week" }, err: `invalid Expiry: "1 week" is not a duration`},
		{name: "bad backdate", mod: func(p *pb.CertProfile) { p.Backdate = "soon" }, err: `invalid Backdate: "soon" is not a duration`},
		{name: "no usages", mod: func(p *pb.CertProfile) { p.Usages = nil }, err: "invalid profile: no usages specified"},
		{name: "unknown usage", mod: func(p *pb.CertProfile) { p.Usages = []string{"flying"} }, err: "invalid profile: unknown usage: flying"},
		{name: "bad extension", mod: func(p *pb.CertProfile) { p.Extensions = []*pb.X509Extension{{ID: "x"}} }, err: "invalid extension OID: x"},
		{name: "bad allowed extension", mod: func(p *pb.CertProfile) { p.AllowedExtensions = []string{"x.y"} }, err: "invalid AllowedExtensions OID: x.y"},
		{name: "bad policy", mod: func(p *pb.CertProfile) { p.Policies = []*pb.CertificatePolicy{{ID: "nope"}} }, err: "invalid Policies OID: nope"},
		{name: "bad qualifier", mod: func(p *pb.CertProfile) { p.Policies[0].Qualifiers[0].Type = "id-qt-other" }, err: "invalid profile: invalid policy qualifier type: id-qt-other"},
		{name: "bad regex", mod: func(p *pb.CertProfile) { p.AllowedDns = "(" }, err: "invalid profile: failed to compile AllowedDNS"},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			var def *pb.CertProfile
			if tc.mod != nil {
				def = fullProfile()
				tc.mod(def)
			}
			_, err := pbconv.ProfileFromPb(def)
			assert.ErrorContains(t, err, tc.err)
		})
	}
}

func TestProfileToPb(t *testing.T) {
	t.Parallel()
	// a definition survives the round trip through the authority profile
	def := fullProfile()
	p, err := pbconv.ProfileFromPb(def)
	require.NoError(t, err)
	back := pbconv.ProfileToPb("server", p)
	assert.Equal(t, "server", back.Label)
	assert.Equal(t, def.IssuerLabel, back.IssuerLabel)
	assert.Equal(t, def.Description, back.Description)
	assert.Equal(t, def.Usages, back.Usages)
	assert.Nil(t, back.CAConstraint, "an empty constraint is omitted")
	assert.Equal(t, def.OcspNoCheck, back.OcspNoCheck)
	assert.Equal(t, "168h0m0s", back.Expiry)
	assert.Equal(t, "30m0s", back.Backdate)
	assert.Equal(t, fmt.Sprint(def.Extensions), fmt.Sprint(back.Extensions))
	assert.Equal(t, def.AllowedExtensions, back.AllowedExtensions)
	assert.Equal(t, def.AllowedNames, back.AllowedNames)
	assert.Equal(t, def.AllowedDns, back.AllowedDns)
	assert.Equal(t, def.AllowedEmail, back.AllowedEmail)
	assert.Equal(t, def.AllowedUri, back.AllowedUri)
	assert.True(t, proto.Equal(def.AllowedFields, back.AllowedFields), back.AllowedFields.String())
	assert.Equal(t, fmt.Sprint(def.Policies), fmt.Sprint(back.Policies))
	assert.Equal(t, def.PoliciesCritical, back.PoliciesCritical)
	assert.Equal(t, def.AllowedRoles, back.AllowedRoles)
	assert.Equal(t, def.DeniedRoles, back.DeniedRoles)
	assert.Empty(t, back.ID, "the identity is the row's")
	assert.Equal(t, pb.ItemStatus_Unknown, back.Status)

	// and the result converts again
	again, err := pbconv.ProfileFromPb(back)
	require.NoError(t, err)
	assert.Equal(t, p.Expiry, again.Expiry)

	// a CA profile keeps its constraint, a file profile without backdate has none
	cap := pbconv.ProfileToPb("ROOT", &authority.CertProfile{
		Expiry:       csr.Duration(10 * 365 * 24 * time.Hour),
		Usage:        []string{"cert sign", "crl sign"},
		CAConstraint: authority.CAConstraint{IsCA: true, MaxPathLen: -1},
	})
	assert.True(t, proto.Equal(&pb.CAConstraint{IsCA: true, MaxPathLen: -1}, cap.CAConstraint), cap.CAConstraint.String())
	assert.Empty(t, cap.Backdate)
	assert.Empty(t, cap.IssuerLabel)
	assert.Nil(t, cap.Extensions)
	assert.Nil(t, cap.AllowedFields)

	// stored and restored by the row
	m, err := model.NewCertificateProfile(xdb.NewID(1), xdb.ID(0), back)
	require.NoError(t, err)
	stored, err := m.Pb()
	require.NoError(t, err)
	assert.Equal(t, back.Expiry, stored.Expiry)
	assert.Equal(t, fmt.Sprint(back.Policies), fmt.Sprint(stored.Policies))
}

func TestExtensionsFromPb(t *testing.T) {
	t.Parallel()
	list, err := pbconv.ExtensionsFromPb(nil)
	require.NoError(t, err)
	assert.Nil(t, list)
	list, err = pbconv.ExtensionsFromPb([]*pb.X509Extension{nil, {ID: "2.5.29.17", Critical: true, Value: "base64:BQA="}})
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, "2.5.29.17", list[0].ID.String())
	assert.True(t, list[0].Critical)
	assert.Equal(t, "base64:BQA=", list[0].Value)
	_, err = pbconv.ExtensionsFromPb([]*pb.X509Extension{{ID: "nope"}})
	assert.EqualError(t, err, "invalid extension OID: nope")
	assert.Nil(t, pbconv.ExtensionsToPb(nil))
	assert.Equal(t, fmt.Sprint([]*pb.X509Extension{{ID: "2.5.29.17", Critical: true, Value: "base64:BQA="}}), fmt.Sprint(pbconv.ExtensionsToPb(list)))
}

func TestIssuerConfig(t *testing.T) {
	t.Parallel()
	// nil settings take the authority defaults
	acfg, err := pbconv.IssuerConfigFromPb("L2", nil)
	require.NoError(t, err)
	assert.Equal(t, "L2", acfg.Label)
	require.NotNil(t, acfg.AIA)
	assert.Equal(t, authority.DefaultCRLExpiry, acfg.AIA.GetCRLExpiry())
	assert.Equal(t, authority.DefaultOCSPExpiry, acfg.AIA.GetOCSPExpiry())
	assert.Equal(t, authority.DefaultCRLRenewal, acfg.AIA.GetCRLRenewal())
	assert.NotNil(t, acfg.Profiles)
	assert.Empty(t, acfg.AllowedProfiles)

	cfg := &pb.IssuerConfig{
		AiaURL:                 "http://cis/v1/cert/${ISSUER_ID}",
		OcspURL:                "http://cis/v1/ocsp/${ISSUER_ID}",
		CrlURL:                 "http://cis/v1/crl/${ISSUER_ID}",
		CrlExpiry:              "48h",
		CrlRenewal:             "12h",
		OcspExpiry:             "1h",
		DelegatedOcspProfile:   "ocsp",
		AllowedProfiles:        []string{"ocsp", "peer"},
		OmitDisabledExtensions: true,
	}
	acfg, err = pbconv.IssuerConfigFromPb("L2", cfg)
	require.NoError(t, err)
	assert.Equal(t, &authority.AIAConfig{
		AiaURL:               cfg.AiaURL,
		OcspURL:              cfg.OcspURL,
		CrlURL:               cfg.CrlURL,
		CRLExpiry:            48 * time.Hour,
		OCSPExpiry:           time.Hour,
		CRLRenewal:           12 * time.Hour,
		DelegatedOCSPProfile: "ocsp",
	}, acfg.AIA)
	assert.Equal(t, []string{"ocsp", "peer"}, acfg.AllowedProfiles)
	assert.True(t, acfg.OmitDisabledExtensions)

	back := pbconv.IssuerConfigToPb(acfg)
	assert.Equal(t, "48h0m0s", back.CrlExpiry)
	assert.Equal(t, "12h0m0s", back.CrlRenewal)
	assert.Equal(t, "1h0m0s", back.OcspExpiry)
	back.CrlExpiry, back.CrlRenewal, back.OcspExpiry = cfg.CrlExpiry, cfg.CrlRenewal, cfg.OcspExpiry
	assert.Equal(t, cfg.String(), back.String())

	// a file issuer without AIA
	assert.True(t, proto.Equal(&pb.IssuerConfig{AllowedProfiles: []string{"a"}}, pbconv.IssuerConfigToPb(&authority.IssuerConfig{AllowedProfiles: []string{"a"}})))

	for _, tc := range []struct {
		cfg *pb.IssuerConfig
		err string
	}{
		{cfg: &pb.IssuerConfig{CrlExpiry: "x"}, err: `invalid CrlExpiry: "x" is not a duration`},
		{cfg: &pb.IssuerConfig{CrlRenewal: "x"}, err: `invalid CrlRenewal: "x" is not a duration`},
		{cfg: &pb.IssuerConfig{OcspExpiry: "x"}, err: `invalid OcspExpiry: "x" is not a duration`},
	} {
		_, err := pbconv.IssuerConfigFromPb("L2", tc.cfg)
		assert.EqualError(t, err, tc.err)
	}
}

// caProfileDef is the profile a parent signs subordinate CAs with
func caProfileDef(label, issuerLabel string) *pb.CertProfile {
	return &pb.CertProfile{
		Label:       label,
		IssuerLabel: issuerLabel,
		Expiry:      "8760h",
		Backdate:    "30m",
		Usages:      []string{"cert sign", "crl sign"},
		CAConstraint: &pb.CAConstraint{
			IsCA: true,
		},
	}
}
