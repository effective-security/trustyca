package model_test

import (
	"testing"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/xdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_CertificateProfile(t *testing.T) {
	t.Parallel()

	def := &pb.CertProfile{
		ID:          "ignored",
		OrgID:       "ignored",
		Label:       "peer",
		IssuerLabel: "L2_CA",
		Description: "peer certificates",
		Usages:      []string{"signing", "server auth"},
		Expiry:      "168h",
		Backdate:    "30m",
		CAConstraint: &pb.CAConstraint{
			IsCA:       false,
			MaxPathLen: -1,
		},
		AllowedExtensions: []string{"2.5.29.17"},
		Policies: []*pb.CertificatePolicy{{
			ID: "2.16.840.1.114569.1.1.3",
			Qualifiers: []*pb.CertificatePolicyQualifier{{
				Type:  "id-qt-cps",
				Value: "https://example.com/cps",
			}},
		}},
	}

	_, err := model.NewCertificateProfile(xdb.NewID(1), xdb.NewID(2), nil)
	assert.EqualError(t, err, "invalid profile: required")

	m, err := model.NewCertificateProfile(xdb.NewID(1), xdb.NewID(2), def)
	require.NoError(t, err)
	require.NoError(t, m.Validate())
	assert.Equal(t, "peer", m.Label)
	assert.Equal(t, "L2_CA", m.IssuerLabel)
	assert.Equal(t, pb.ItemStatus_Active, m.Status, "the status defaults to Active")
	cfg := m.Config.String()
	assert.NotContains(t, cfg, "ignored", "the identity columns are not stored in the config")
	assert.NotContains(t, cfg, `"Label"`)
	assert.NotContains(t, cfg, `"IssuerLabel"`)
	assert.Contains(t, cfg, `"Expiry":"168h"`)
	assert.Contains(t, cfg, `"MaxPathLen":-1`)

	m.ID = xdb.NewID(3)
	p, err := m.Pb()
	require.NoError(t, err)
	assert.Equal(t, "3", p.ID)
	assert.Equal(t, "1", p.OrgID)
	assert.Equal(t, "2", p.ProjectID)
	assert.Equal(t, "peer", p.Label)
	assert.Equal(t, "L2_CA", p.IssuerLabel)
	assert.Equal(t, pb.ItemStatus_Active, p.Status)
	assert.Equal(t, def.Description, p.Description)
	assert.Equal(t, def.Usages, p.Usages)
	assert.Equal(t, def.Expiry, p.Expiry)
	assert.Equal(t, def.Backdate, p.Backdate)
	assert.EqualValues(t, -1, p.CAConstraint.MaxPathLen)
	assert.Equal(t, def.AllowedExtensions, p.AllowedExtensions)
	require.Len(t, p.Policies, 1)
	assert.Equal(t, "https://example.com/cps", p.Policies[0].Qualifiers[0].Value)
	assert.Equal(t, "ignored", def.ID, "the definition is not modified")

	m.Config = model.JSON(`{`)
	_, err = m.Pb()
	assert.ErrorContains(t, err, "invalid config of profile 3")
	assert.EqualError(t, m.SetConfig(nil), "invalid profile: required")

	tcases := []struct {
		name string
		mod  func(m *model.CertificateProfile)
		err  string
	}{
		{"project without org", func(m *model.CertificateProfile) { m.OrgID = xdb.ID{} }, "invalid org ID: a project scope requires an org"},
		{"label", func(m *model.CertificateProfile) { m.Label = "" }, "invalid label: required"},
		{"issuer label", func(m *model.CertificateProfile) { m.IssuerLabel = "" }, "invalid issuer label: required"},
		{"status", func(m *model.CertificateProfile) { m.Status = pb.ItemStatus_Unknown }, "invalid profile status"},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := model.NewCertificateProfile(xdb.NewID(1), xdb.NewID(2), def)
			require.NoError(t, err)
			tc.mod(m)
			assert.EqualError(t, m.Validate(), tc.err)
		})
	}

	m, err = model.NewCertificateProfile(xdb.ID{}, xdb.ID{}, &pb.CertProfile{Label: "ocsp", IssuerLabel: model.AnyIssuerLabel, Status: pb.ItemStatus_Inactive})
	require.NoError(t, err)
	require.NoError(t, m.Validate())
	assert.Equal(t, pb.ItemStatus_Inactive, m.Status)

	res := &model.CertificateProfileResult{Rows: model.CertificateProfileSlice{m}, HasNextPage: true, Cursor: "c"}
	pres, err := res.Pb()
	require.NoError(t, err)
	require.Len(t, pres.Profiles, 1)
	assert.Equal(t, "ocsp", pres.Profiles[0].Label)
	assert.Equal(t, "c", pres.NextPage.Cursor)
	m.Config = model.JSON(`{`)
	_, err = res.Pb()
	assert.Error(t, err)
}
