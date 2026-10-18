package pgsql_test

import (
	"testing"
	"time"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/tests/testutils"
	"github.com/effective-security/xdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Crl(t *testing.T) {
	_, org := setupOwnerAndOrg(t, "Test_Crl")

	root := testutils.NewTestCA(t, "CRL Root", nil)
	ca := testutils.NewTestCA(t, "CRL L2", root)
	issuer := registerIssuer(t, newTestIssuer(org.ID, xdb.ID{}, "CRL_L2", ca, pb.AuthorityType_Issuing, xdb.ID{}))
	now := xdb.Now()

	newCrl := func(number int64, pem string) *model.Crl {
		return &model.Crl{
			OrgID:      org.ID,
			IssuerID:   issuer.ID,
			Ikid:       issuer.Skid,
			CrlNumber:  number,
			ThisUpdate: now,
			NextUpdate: now.Add(48 * time.Hour),
			Issuer:     issuer.Subject,
			Pem:        pem,
		}
	}

	_, err := provider.PublishCrl(ctx, &model.Crl{})
	assert.EqualError(t, err, "invalid issuer ID")
	unknown := newCrl(1, "crl")
	unknown.IssuerID = xdb.NewID(1)
	_, err = provider.PublishCrl(ctx, unknown)
	assert.ErrorContains(t, err, "record not found: issuer: 1")

	crl1, err := provider.PublishCrl(ctx, newCrl(1, "crl-1"))
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = provider.DeleteCrl(ctx, org.ID.UInt64(), issuer.Skid)
	})
	assert.EqualValues(t, 1, crl1.CrlNumber)
	assert.Equal(t, issuer.Skid, crl1.Ikid)
	assert.Equal(t, org.ID.UInt64(), crl1.OrgID.UInt64())
	assert.Equal(t, issuer.Subject, crl1.Issuer)
	assert.Equal(t, "crl-1", crl1.Pem)
	assert.Empty(t, crl1.Locations)
	assert.Equal(t, now.UnixMilli(), crl1.ThisUpdate.UnixMilli())
	assert.False(t, crl1.CreatedAt.IsZero())

	iss, err := provider.GetIssuer(ctx, issuer.ID.UInt64())
	require.NoError(t, err)
	assert.EqualValues(t, 1, iss.CrlNumber, "the issuer records the published number")
	assert.Equal(t, issuer.UpdatedAt.UnixMilli(), iss.UpdatedAt.UnixMilli(), "publishing does not touch updated_at")

	// the same number again: nothing changes
	_, err = provider.PublishCrl(ctx, newCrl(1, "crl-stale"))
	assert.ErrorIs(t, err, db.ErrStaleCrlNumber)
	got, err := provider.GetCrl(ctx, issuer.Skid)
	require.NoError(t, err)
	assert.Equal(t, "crl-1", got.Pem, "the stale CRL is not stored")
	assert.EqualValues(t, 1, got.CrlNumber)
	iss, err = provider.GetIssuer(ctx, issuer.ID.UInt64())
	require.NoError(t, err)
	assert.EqualValues(t, 1, iss.CrlNumber)

	// the next number replaces the CRL and keeps its row
	m := newCrl(2, "crl-2")
	m.ThisUpdate = now.Add(time.Hour)
	m.NextUpdate = now.Add(49 * time.Hour)
	m.Locations = []string{"https://cis/v1/crl/" + issuer.Skid}
	crl2, err := provider.PublishCrl(ctx, m)
	require.NoError(t, err)
	assert.Equal(t, crl1.ID.UInt64(), crl2.ID.UInt64())
	assert.EqualValues(t, 2, crl2.CrlNumber)
	assert.Equal(t, "crl-2", crl2.Pem)
	assert.Equal(t, []string{"https://cis/v1/crl/" + issuer.Skid}, []string(crl2.Locations))
	assert.Equal(t, now.Add(49*time.Hour).UnixMilli(), crl2.NextUpdate.UnixMilli())
	assert.Equal(t, crl1.CreatedAt.UnixMilli(), crl2.CreatedAt.UnixMilli())
	iss, err = provider.GetIssuer(ctx, issuer.ID.UInt64())
	require.NoError(t, err)
	assert.EqualValues(t, 2, iss.CrlNumber)

	// the tenancy and issuer name come from the issuer row, not the caller
	foreign := newCrl(3, "crl-3")
	foreign.OrgID = xdb.NewID(org.ID.UInt64() + 1)
	foreign.ProjectID = xdb.NewID(42)
	foreign.Issuer = "CN=Someone Else"
	crl3, err := provider.PublishCrl(ctx, foreign)
	require.NoError(t, err)
	assert.Equal(t, org.ID.UInt64(), crl3.OrgID.UInt64())
	assert.True(t, crl3.ProjectID.IsZero())
	assert.Equal(t, issuer.Subject, crl3.Issuer)

	// a gap is allowed: an imported issuer continues its own numbering
	crl10, err := provider.PublishCrl(ctx, newCrl(10, "crl-10"))
	require.NoError(t, err)
	assert.EqualValues(t, 10, crl10.CrlNumber)
	p := crl10.Pb()
	assert.Equal(t, "10", p.Number)
	assert.Equal(t, issuer.ID.String(), p.IssuerID)

	// get and list
	_, err = provider.GetCrl(ctx, "nope")
	assert.ErrorContains(t, err, "record not found: crl: nope")

	list, err := provider.ListCrls(ctx, &query.ListCrlsRequest{OrgID: org.ID.UInt64(), Limit: 10})
	require.NoError(t, err)
	require.Len(t, list.Rows, 1)
	assert.Equal(t, crl1.ID.UInt64(), list.Rows[0].ID.UInt64())
	assert.Len(t, list.Pb().Crls, 1)

	in50h := now.Add(50 * time.Hour).UTC()
	list, err = provider.ListCrls(ctx, &query.ListCrlsRequest{OrgID: org.ID.UInt64(), ExpiringBefore: &in50h, Limit: 10})
	require.NoError(t, err)
	require.Len(t, list.Rows, 1)
	in1h := now.Add(time.Hour).UTC()
	list, err = provider.ListCrls(ctx, &query.ListCrlsRequest{OrgID: org.ID.UInt64(), ExpiringBefore: &in1h, Limit: 10})
	require.NoError(t, err)
	assert.Empty(t, list.Rows, "the CRL is not due")
	list, err = provider.ListCrls(ctx, &query.ListCrlsRequest{OrgID: org.ID.UInt64(), Scope: pb.Scope_Project, Limit: 10})
	require.NoError(t, err)
	assert.Empty(t, list.Rows)
	list, err = provider.ListCrls(ctx, &query.ListCrlsRequest{Platform: true, Limit: 500})
	require.NoError(t, err)
	for _, r := range list.Rows {
		assert.True(t, r.OrgID.IsZero())
	}
	_, err = provider.ListCrls(ctx, &query.ListCrlsRequest{Limit: 10})
	assert.ErrorIs(t, err, db.ErrOrgScopeRequired)

	// a second issuer for cursor pagination
	other := registerIssuer(t, newTestIssuer(org.ID, xdb.ID{}, "CRL_OTHER", testutils.NewTestCA(t, "CRL Other", root), pb.AuthorityType_Issuing, xdb.ID{}))
	otherCrl := newCrl(1, "other")
	otherCrl.IssuerID = other.ID
	otherCrl.Ikid = other.Skid
	oc, err := provider.PublishCrl(ctx, otherCrl)
	require.NoError(t, err)

	// the CRL's IKID must be the SKID of the issuer whose number it bumps
	mixed := newCrl(11, "crl-mixed")
	mixed.Ikid = other.Skid
	_, err = provider.PublishCrl(ctx, mixed)
	assert.ErrorContains(t, err, "does not match issuer")
	iss, err = provider.GetIssuer(ctx, issuer.ID.UInt64())
	require.NoError(t, err)
	assert.EqualValues(t, 10, iss.CrlNumber, "the issuer number is unchanged")
	otherIss, err := provider.GetIssuer(ctx, other.ID.UInt64())
	require.NoError(t, err)
	assert.EqualValues(t, 1, otherIss.CrlNumber)
	got, err = provider.GetCrl(ctx, other.Skid)
	require.NoError(t, err)
	assert.Equal(t, "other", got.Pem, "the other issuer's CRL is unchanged")
	assert.Equal(t, other.ID.UInt64(), got.IssuerID.UInt64())

	list, err = provider.ListCrls(ctx, &query.ListCrlsRequest{OrgID: org.ID.UInt64(), Limit: 1, Cursor: query.NewCursor(0)})
	require.NoError(t, err)
	require.Len(t, list.Rows, 1)
	assert.Equal(t, oc.ID.UInt64(), list.Rows[0].ID.UInt64())
	require.True(t, list.HasNextPage)
	next, err := query.ParseCursor(list.Cursor)
	require.NoError(t, err)
	list, err = provider.ListCrls(ctx, &query.ListCrlsRequest{OrgID: org.ID.UInt64(), Limit: 1, Cursor: next})
	require.NoError(t, err)
	require.Len(t, list.Rows, 1)
	assert.Equal(t, crl1.ID.UInt64(), list.Rows[0].ID.UInt64())

	// deleting the issuer deletes its CRL
	n, err := provider.DeleteIssuer(ctx, org.ID.UInt64(), other.ID.UInt64())
	require.NoError(t, err)
	assert.EqualValues(t, 1, n)
	_, err = provider.GetCrl(ctx, other.Skid)
	assert.ErrorContains(t, err, "record not found")

	// delete is scoped by org
	n, err = provider.DeleteCrl(ctx, 0, issuer.Skid)
	require.NoError(t, err)
	assert.EqualValues(t, 0, n)
	n, err = provider.DeleteCrl(ctx, org.ID.UInt64(), issuer.Skid)
	require.NoError(t, err)
	assert.EqualValues(t, 1, n)
	n, err = provider.DeleteCrl(ctx, org.ID.UInt64(), issuer.Skid)
	require.NoError(t, err)
	assert.EqualValues(t, 0, n)
}
