package model_test

import (
	"testing"
	"time"

	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/xdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Crl(t *testing.T) {
	t.Parallel()

	now := xdb.Now()
	m := &model.Crl{
		ID:         xdb.NewID(1),
		OrgID:      xdb.NewID(2),
		IssuerID:   xdb.NewID(3),
		Ikid:       "0102",
		CrlNumber:  7,
		ThisUpdate: now,
		NextUpdate: now.Add(48 * time.Hour),
		Issuer:     "CN=Test L2",
		Pem:        "-----BEGIN X509 CRL-----",
		Locations:  []string{"https://cis/v1/crl/0102"},
	}
	require.NoError(t, m.Validate())

	p := m.Pb()
	assert.Equal(t, "1", p.ID)
	assert.Equal(t, "2", p.OrgID)
	assert.Equal(t, "3", p.IssuerID)
	assert.Equal(t, "0102", p.IKID)
	assert.Equal(t, "7", p.Number)
	assert.Equal(t, m.ThisUpdate.String(), p.ThisUpdate)
	assert.Equal(t, m.NextUpdate.String(), p.NextUpdate)
	assert.Equal(t, "CN=Test L2", p.Issuer)
	assert.Equal(t, m.Pem, p.Pem)
	assert.Equal(t, []string{"https://cis/v1/crl/0102"}, p.Locations)

	tcases := []struct {
		name string
		mod  func(m *model.Crl)
		err  string
	}{
		{"project without org", func(m *model.Crl) { m.OrgID = xdb.ID{}; m.ProjectID = xdb.NewID(4) }, "invalid org ID: a project scope requires an org"},
		{"issuer id", func(m *model.Crl) { m.IssuerID = xdb.ID{} }, "invalid issuer ID"},
		{"ikid", func(m *model.Crl) { m.Ikid = "" }, "invalid ikid: required"},
		{"number", func(m *model.Crl) { m.CrlNumber = 0 }, "invalid crl number: must be positive"},
		{"period", func(m *model.Crl) { m.NextUpdate = m.ThisUpdate }, "invalid update period"},
		{"issuer", func(m *model.Crl) { m.Issuer = "" }, "invalid issuer: required"},
		{"location", func(m *model.Crl) { m.Locations = []string{""} }, "invalid location: required"},
		{"pem", func(m *model.Crl) { m.Pem = "" }, "invalid pem: required"},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			c := *m
			tc.mod(&c)
			assert.EqualError(t, c.Validate(), tc.err)
		})
	}

	res := &model.CrlResult{Rows: model.CrlSlice{m}, HasNextPage: true, Cursor: "c"}
	assert.Len(t, res.Pb().Crls, 1)
	assert.Equal(t, "c", res.NextPage().Cursor)
	res.HasNextPage = false
	assert.Nil(t, res.NextPage())
}
