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

func Test_Certificate(t *testing.T) {
	t.Parallel()

	root := testutils.NewTestCA(t, "Test Root", nil)
	ca := testutils.NewTestCA(t, "Test L2", root)
	now := time.Now().Truncate(time.Second)
	crt := ca.Issue(t, "peer.example.com", now.Add(-time.Minute), now.Add(time.Hour))
	pem := testutils.CertPEM(crt)
	issuers := testutils.CertPEM(ca.Cert) + ca.ChainPEM()

	m := model.NewCertificate(crt, xdb.NewID(1), xdb.NewID(2), "peer", pem, issuers, "edge-1", []string{"https://cis/v1/cert/1"}, xdb.Metadata{"requester": "ci"})
	m.Status = pb.CertificateStatus_Active
	require.NoError(t, m.Validate())
	assert.Equal(t, certutil.GetSubjectKeyID(crt), m.Skid)
	assert.Equal(t, certutil.GetSubjectKeyID(ca.Cert), m.Ikid)
	assert.Equal(t, crt.SerialNumber.String(), m.SerialNumber)
	assert.Equal(t, "CN=peer.example.com,O=trustyca tests", m.Subject)
	assert.Equal(t, "CN=Test L2,O=trustyca tests", m.Issuer)
	assert.Equal(t, certutil.SHA256Hex(crt.Raw), m.Sha256)
	assert.Equal(t, now.Add(time.Hour).UnixMilli(), m.NotAfter.UnixMilli())
	assert.False(t, m.IsExpired(now))
	assert.True(t, m.IsExpired(now.Add(2*time.Hour)))

	m.ID = xdb.NewID(3)
	m.Label = "edge-1"
	m.Locations = []string{"https://cis/v1/cert/3"}
	m.Metadata = xdb.Metadata{"requester": "ci"}
	p := m.Pb()
	assert.Equal(t, "3", p.ID)
	assert.Equal(t, "1", p.OrgID)
	assert.Equal(t, "2", p.ProjectID)
	assert.Equal(t, m.Skid, p.SKID)
	assert.Equal(t, m.Ikid, p.IKID)
	assert.Equal(t, m.SerialNumber, p.SerialNumber)
	assert.Equal(t, m.NotBefore.String(), p.NotBefore)
	assert.Equal(t, m.NotAfter.String(), p.NotAfter)
	assert.Equal(t, "peer", p.Profile)
	assert.Equal(t, pem, p.Pem)
	assert.Equal(t, issuers, p.IssuersPem)
	assert.Equal(t, []string{"https://cis/v1/cert/3"}, p.Locations)
	assert.Equal(t, "edge-1", p.Label)
	assert.Equal(t, map[string]string{"requester": "ci"}, p.Metadata)
	assert.Equal(t, pb.CertificateStatus_Active, p.Status)

	tcases := []struct {
		name string
		mod  func(m *model.Certificate)
		err  string
	}{
		{"project without org", func(m *model.Certificate) { m.OrgID = xdb.ID{} }, "invalid org ID: a project scope requires an org"},
		{"skid", func(m *model.Certificate) { m.Skid = "" }, "invalid skid: required"},
		{"ikid", func(m *model.Certificate) { m.Ikid = "" }, "invalid ikid: required"},
		{"serial", func(m *model.Certificate) { m.SerialNumber = "" }, "invalid serial number: required"},
		{"subject", func(m *model.Certificate) { m.Subject = "" }, "invalid subject: required"},
		{"issuer", func(m *model.Certificate) { m.Issuer = "" }, "invalid issuer: required"},
		{"sha256", func(m *model.Certificate) { m.Sha256 = "abc" }, "invalid sha256 length"},
		{"profile", func(m *model.Certificate) { m.Profile = "" }, "invalid profile: required"},
		{"label length", func(m *model.Certificate) { m.Label = string(make([]byte, 261)) }, "invalid label length: 261"},
		{"location", func(m *model.Certificate) { m.Locations = []string{""} }, "invalid location: required"},
		{"validity", func(m *model.Certificate) { m.NotAfter = m.NotBefore }, "invalid validity period"},
		{"pem", func(m *model.Certificate) { m.Pem = "" }, "invalid pem: required"},
		{"status", func(m *model.Certificate) { m.Status = pb.CertificateStatus_Unknown }, "invalid certificate status"},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			m := model.NewCertificate(crt, xdb.NewID(1), xdb.NewID(2), "peer", pem, issuers, "edge-1", []string{"https://cis/v1/cert/1"}, xdb.Metadata{"requester": "ci"})
			m.Status = pb.CertificateStatus_Active
			tc.mod(m)
			assert.EqualError(t, m.Validate(), tc.err)
		})
	}

	res := &model.CertificateResult{Rows: model.CertificateSlice{m}, HasNextPage: true, Cursor: "c"}
	pres := res.Pb()
	require.Len(t, pres.Certificates, 1)
	assert.Equal(t, "c", pres.NextPage.Cursor)
	res.HasNextPage = false
	assert.Nil(t, res.Pb().NextPage)
}
