package model_test

import (
	"testing"
	"time"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/tests/testutils"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xpki/certutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validIssuer(t *testing.T) (*model.Issuer, *testutils.TestCA) {
	t.Helper()
	root := testutils.NewTestCA(t, "Test Root", nil)
	ca := testutils.NewTestCA(t, "Test L1", root)
	m := &model.Issuer{
		OrgID:       xdb.NewID(1),
		ProjectID:   xdb.NewID(2),
		Label:       "L1",
		Type:        pb.AuthorityType_Intermediate,
		Status:      pb.IssuerStatus_Active,
		KeyProvider: "inmem",
		KeyID:       "trustyca/1/2/L1",
	}
	m.SetCertificate(ca.Cert, testutils.CertPEM(ca.Cert), ca.ChainPEM(), testutils.CertPEM(root.Cert))
	return m, ca
}

func Test_Issuer_Validate(t *testing.T) {
	t.Parallel()

	m, ca := validIssuer(t)
	require.NoError(t, m.Validate())
	assert.Equal(t, certutil.GetSubjectKeyID(ca.Cert), m.Skid)
	assert.Equal(t, certutil.GetSubjectKeyID(ca.Parent.Cert), m.Ikid, "the IKID is the parent's SKID")
	assert.Equal(t, ca.Cert.SerialNumber.String(), m.SerialNumber)
	assert.Equal(t, "CN=Test L1,O=trustyca tests", m.Subject)
	assert.Equal(t, "CN=Test Root,O=trustyca tests", m.Issuer)
	assert.Equal(t, certutil.SHA256Hex(ca.Cert.Raw), m.Sha256)
	assert.Equal(t, ca.Cert.NotAfter.Truncate(time.Millisecond).UnixMilli(), m.NotAfter.UnixMilli())
	assert.Equal(t, testutils.CertPEM(ca.Parent.Cert), m.ChainPem)

	tcases := []struct {
		name string
		mod  func(m *model.Issuer)
		err  string
	}{
		{"project without org", func(m *model.Issuer) { m.OrgID = xdb.ID{} }, "invalid org ID: a project scope requires an org"},
		{"label", func(m *model.Issuer) { m.Label = "" }, "invalid label: required"},
		{"label length", func(m *model.Issuer) { m.Label = string(make([]byte, 65)) }, "invalid label length: 65"},
		{"type", func(m *model.Issuer) { m.Type = pb.AuthorityType_Unknown }, "invalid issuer type"},
		{"status", func(m *model.Issuer) { m.Status = pb.IssuerStatus_Unknown }, "invalid issuer status"},
		{"skid", func(m *model.Issuer) { m.Skid = "" }, "invalid skid: required"},
		{"key provider", func(m *model.Issuer) { m.KeyProvider = "" }, "invalid key provider: required"},
		{"key id", func(m *model.Issuer) { m.KeyID = "" }, "invalid key ID: required"},
		{"serial", func(m *model.Issuer) { m.SerialNumber = "" }, "invalid serial number: required"},
		{"subject", func(m *model.Issuer) { m.Subject = "" }, "invalid subject: required"},
		{"issuer", func(m *model.Issuer) { m.Issuer = "" }, "invalid issuer: required"},
		{"sha256", func(m *model.Issuer) { m.Sha256 = "abc" }, "invalid sha256 length"},
		{"validity", func(m *model.Issuer) { m.NotAfter = m.NotBefore }, "invalid validity period"},
		{"pem", func(m *model.Issuer) { m.Pem = "" }, "invalid pem: required"},
		{"pending csr", func(m *model.Issuer) { m.Status = pb.IssuerStatus_Pending }, "invalid csr: required for a pending issuer"},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			m, _ := validIssuer(t)
			tc.mod(m)
			assert.EqualError(t, m.Validate(), tc.err)
		})
	}

	// a pending issuer needs the CSR and subject, not the certificate
	pending := &model.Issuer{
		OrgID:       xdb.NewID(1),
		Label:       "pending",
		Type:        pb.AuthorityType_Issuing,
		Status:      pb.IssuerStatus_Pending,
		Skid:        "0102",
		Subject:     "CN=pending",
		KeyProvider: "inmem",
		KeyID:       "trustyca/1/0/pending",
		CsrPem:      "-----BEGIN CERTIFICATE REQUEST-----",
	}
	require.NoError(t, pending.Validate())
	// a platform issuer has no org
	m.OrgID = xdb.ID{}
	m.ProjectID = xdb.ID{}
	require.NoError(t, m.Validate())
}

func Test_Issuer_Config_Pb(t *testing.T) {
	t.Parallel()

	m, _ := validIssuer(t)
	m.ID = xdb.NewID(10)
	m.ParentID = xdb.NewID(9)
	m.KeyProtected = "wrapped"
	m.CrlNumber = 7

	cfg, err := m.GetConfig()
	require.NoError(t, err)
	require.NotNil(t, cfg, "an empty config is an empty message")
	assert.Empty(t, cfg.AllowedProfiles)

	require.NoError(t, m.SetConfig(&pb.IssuerConfig{
		CrlURL:          "https://cis/v1/crl/${ISSUER_ID}",
		AllowedProfiles: []string{"peer"},
	}))
	cfg, err = m.GetConfig()
	require.NoError(t, err)
	assert.Equal(t, "https://cis/v1/crl/${ISSUER_ID}", cfg.CrlURL)
	assert.Equal(t, []string{"peer"}, cfg.AllowedProfiles)

	p, err := m.Pb()
	require.NoError(t, err)
	assert.Equal(t, "10", p.ID)
	assert.Equal(t, "1", p.OrgID)
	assert.Equal(t, "2", p.ProjectID)
	assert.Equal(t, "9", p.ParentID)
	assert.Equal(t, "L1", p.Label)
	assert.Equal(t, pb.AuthorityType_Intermediate, p.Type)
	assert.Equal(t, pb.IssuerStatus_Active, p.Status)
	assert.Equal(t, m.Skid, p.SKID)
	assert.Equal(t, m.Ikid, p.IKID)
	assert.Equal(t, m.Pem, p.Certificate)
	assert.Equal(t, m.ChainPem, p.Intermediates)
	assert.Equal(t, m.RootPem, p.Root)
	assert.Equal(t, "inmem", p.KeyProvider)
	assert.Equal(t, "7", p.CrlNumber)
	assert.Equal(t, []string{"peer"}, p.Config.AllowedProfiles)
	assert.Empty(t, p.Profiles, "profiles are resolved by the service")

	// the config is cleared with nil
	require.NoError(t, m.SetConfig(nil))
	assert.True(t, m.Config.IsEmpty())

	m.Config = model.JSON(`{`)
	_, err = m.GetConfig()
	assert.ErrorContains(t, err, "invalid config of issuer 10")
	_, err = m.Pb()
	assert.Error(t, err)

	res := &model.IssuerResult{Rows: model.IssuerSlice{m}, HasNextPage: true, Cursor: "c"}
	_, err = res.Pb()
	assert.Error(t, err)
	m.Config = nil
	pres, err := res.Pb()
	require.NoError(t, err)
	require.Len(t, pres.Issuers, 1)
	require.NotNil(t, pres.NextPage)
	assert.Equal(t, "c", pres.NextPage.Cursor)
	res.HasNextPage = false
	assert.Nil(t, res.NextPage())
}
