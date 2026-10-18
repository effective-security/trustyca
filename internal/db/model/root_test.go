package model_test

import (
	"testing"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/tests/testutils"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xpki/certutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_RootCertificate(t *testing.T) {
	t.Parallel()

	root := testutils.NewTestCA(t, "Test Root", nil)
	pem := testutils.CertPEM(root.Cert)
	m := model.NewRootCertificate(root.Cert, xdb.NewID(1), pb.Trust_Private, pem)
	require.NoError(t, m.Validate())
	assert.Equal(t, certutil.GetSubjectKeyID(root.Cert), m.Skid)
	assert.Equal(t, certutil.SHA256Hex(root.Cert.Raw), m.Sha256)
	assert.Equal(t, "CN=Test Root,O=trustyca tests", m.Subject)
	assert.Equal(t, root.Cert.NotBefore.UnixMilli(), m.NotBefore.UnixMilli())
	assert.Equal(t, root.Cert.NotAfter.UnixMilli(), m.NotAfter.UnixMilli())

	m.ID = xdb.NewID(5)
	p := m.Pb()
	assert.Equal(t, "5", p.ID)
	assert.Equal(t, "1", p.OrgID)
	assert.Equal(t, m.Skid, p.SKID)
	assert.Equal(t, m.Sha256, p.Sha256)
	assert.Equal(t, pb.Trust_Private, p.Trust)
	assert.Equal(t, pem, p.Pem)
	assert.Equal(t, m.NotAfter.String(), p.NotAfter)

	// platform root
	platform := model.NewRootCertificate(root.Cert, xdb.ID{}, pb.Trust_Any, pem)
	require.NoError(t, platform.Validate())
	assert.Empty(t, platform.Pb().OrgID)

	tcases := []struct {
		name string
		mod  func(m *model.RootCertificate)
		err  string
	}{
		{"skid", func(m *model.RootCertificate) { m.Skid = "" }, "invalid skid: required"},
		{"subject", func(m *model.RootCertificate) { m.Subject = "" }, "invalid subject: required"},
		{"sha256", func(m *model.RootCertificate) { m.Sha256 = "abc" }, "invalid sha256 length"},
		{"validity", func(m *model.RootCertificate) { m.NotBefore = xdb.Time{} }, "invalid validity period"},
		{"pem", func(m *model.RootCertificate) { m.Pem = "" }, "invalid pem: required"},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			m := model.NewRootCertificate(root.Cert, xdb.NewID(1), pb.Trust_Private, pem)
			tc.mod(m)
			assert.EqualError(t, m.Validate(), tc.err)
		})
	}

	res := &model.RootCertificateResult{Rows: model.RootCertificateSlice{m}, HasNextPage: true, NextOffset: 1}
	pres := res.Pb()
	require.Len(t, pres.Roots, 1)
	require.NotNil(t, pres.NextPage)
	assert.EqualValues(t, 1, pres.NextPage.Offset)
}
