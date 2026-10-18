package model_test

import (
	"testing"
	"time"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/tests/testutils"
	"github.com/effective-security/xdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Revoked(t *testing.T) {
	t.Parallel()

	root := testutils.NewTestCA(t, "Test Root", nil)
	now := time.Now()
	crt := root.Issue(t, "peer.example.com", now.Add(-time.Minute), now.Add(time.Hour))
	c := model.NewCertificate(crt, xdb.NewID(1), xdb.NewID(2), "peer", testutils.CertPEM(crt), testutils.CertPEM(root.Cert), "edge-1", nil, nil)
	c.ID = xdb.NewID(3)
	c.Status = pb.CertificateStatus_Revoked
	c.Label = "edge-1"
	c.Locations = []string{"https://cis/v1/cert/3"}
	c.Metadata = xdb.Metadata{"requester": "ci"}
	c.CreatedAt = xdb.Now()

	r := &model.Revoked{
		ID:            xdb.NewID(4),
		OrgID:         c.OrgID,
		ProjectID:     c.ProjectID,
		CertificateID: c.ID,
		Ikid:          c.Ikid,
		SerialNumber:  c.SerialNumber,
		NotAfter:      c.NotAfter,
		RevokedAt:     xdb.UTC(now),
		Reason:        pb.ReasonCode_KeyCompromise,
		ReasonText:    "laptop stolen",
	}
	require.NoError(t, r.Validate())

	tcases := []struct {
		name string
		mod  func(m *model.Revoked)
		err  string
	}{
		{"project without org", func(m *model.Revoked) { m.OrgID = xdb.ID{} }, "invalid org ID: a project scope requires an org"},
		{"certificate", func(m *model.Revoked) { m.CertificateID = xdb.ID{} }, "invalid certificate ID"},
		{"ikid", func(m *model.Revoked) { m.Ikid = "" }, "invalid ikid: required"},
		{"serial", func(m *model.Revoked) { m.SerialNumber = "" }, "invalid serial number: required"},
		{"reason text", func(m *model.Revoked) { m.ReasonText = string(make([]byte, 261)) }, "invalid reason text length: 261"},
		{"not after", func(m *model.Revoked) { m.NotAfter = xdb.Time{} }, "invalid not after time"},
		{"revoked at", func(m *model.Revoked) { m.RevokedAt = xdb.Time{} }, "invalid revocation time"},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			m := *r
			tc.mod(&m)
			assert.EqualError(t, m.Validate(), tc.err)
		})
	}

	rc := model.NewRevokedCertificate(c, r)
	assert.Equal(t, r.ID.UInt64(), rc.ID.UInt64(), "the row ID is the revocation")
	assert.Equal(t, c.ID.UInt64(), rc.CertificateID.UInt64())
	assert.Equal(t, *c, *rc.Certificate(), "the certificate columns round trip")

	p := rc.Pb()
	assert.Equal(t, "3", p.Certificate.ID)
	assert.Equal(t, "1", p.Certificate.OrgID)
	assert.Equal(t, "2", p.Certificate.ProjectID)
	assert.Equal(t, c.Sha256, p.Certificate.Sha256)
	assert.Equal(t, c.Pem, p.Certificate.Pem)
	assert.Equal(t, pb.CertificateStatus_Revoked, p.Certificate.Status)
	assert.Equal(t, r.RevokedAt.String(), p.RevokedAt)
	assert.Equal(t, pb.ReasonCode_KeyCompromise, p.Reason)
	assert.Equal(t, "laptop stolen", p.ReasonText)

	res := &model.RevokedCertificateResult{Rows: model.RevokedCertificateSlice{rc}, HasNextPage: true, Cursor: "c"}
	pres := res.Pb()
	require.Len(t, pres.RevokedCertificates, 1)
	assert.Equal(t, "c", pres.NextPage.Cursor)

	rres := &model.RevokedResult{Rows: model.RevokedSlice{r}, HasNextPage: true, NextOffset: 5}
	assert.EqualValues(t, 5, rres.NextPage().Offset)
	rres.HasNextPage = false
	assert.Nil(t, rres.NextPage())
}
