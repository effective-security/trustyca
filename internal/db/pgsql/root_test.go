package pgsql_test

import (
	"testing"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/tests/testutils"
	"github.com/effective-security/xdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Root(t *testing.T) {
	_, orgA := setupOwnerAndOrg(t, "Test_Root_A")
	_, orgB := setupOwnerAndOrg(t, "Test_Root_B")

	root := testutils.NewTestCA(t, "Trust Anchor", nil)
	pem := testutils.CertPEM(root.Cert)

	_, err := provider.RegisterRoot(ctx, &model.RootCertificate{})
	assert.EqualError(t, err, "invalid skid: required")

	ra, err := provider.RegisterRoot(ctx, model.NewRootCertificate(root.Cert, orgA.ID, pb.Trust_Private, pem))
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = provider.DeleteRoot(ctx, orgA.ID.UInt64(), ra.ID.UInt64())
	})
	assert.Equal(t, orgA.ID.UInt64(), ra.OrgID.UInt64())
	assert.Equal(t, pb.Trust_Private, ra.Trust)
	assert.Equal(t, pem, ra.Pem)
	assert.Equal(t, "CN=Trust Anchor,O=trustyca tests", ra.Subject)
	assert.False(t, ra.CreatedAt.IsZero())

	// the same certificate in the same scope updates the trust
	again, err := provider.RegisterRoot(ctx, model.NewRootCertificate(root.Cert, orgA.ID, pb.Trust_Public, pem))
	require.NoError(t, err)
	assert.Equal(t, ra.ID.UInt64(), again.ID.UInt64())
	assert.Equal(t, pb.Trust_Public, again.Trust)

	// the same certificate in another scope conflicts
	_, err = provider.RegisterRoot(ctx, model.NewRootCertificate(root.Cert, orgB.ID, pb.Trust_Private, pem))
	assert.ErrorIs(t, err, db.ErrRootConflict)
	_, err = provider.RegisterRoot(ctx, model.NewRootCertificate(root.Cert, xdb.ID(0), pb.Trust_Private, pem))
	assert.ErrorIs(t, err, db.ErrRootConflict)

	// platform root
	platform := testutils.NewTestCA(t, "Platform Root", nil)
	pr, err := provider.RegisterRoot(ctx, model.NewRootCertificate(platform.Cert, xdb.ID(0), pb.Trust_Any, testutils.CertPEM(platform.Cert)))
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = provider.DeleteRoot(ctx, 0, pr.ID.UInt64())
	})
	assert.True(t, pr.OrgID.IsZero())

	// a second root of org A
	second := testutils.NewTestCA(t, "Second Anchor", nil)
	rb, err := provider.RegisterRoot(ctx, model.NewRootCertificate(second.Cert, orgA.ID, pb.Trust_Private, testutils.CertPEM(second.Cert)))
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = provider.DeleteRoot(ctx, orgA.ID.UInt64(), rb.ID.UInt64())
	})

	// get
	got, err := provider.GetRoot(ctx, ra.ID.UInt64())
	require.NoError(t, err)
	assert.Equal(t, ra.Sha256, got.Sha256)
	_, err = provider.GetRoot(ctx, 1)
	assert.ErrorContains(t, err, "record not found: root_certificate: 1")

	// list
	list, err := provider.ListRoots(ctx, &query.ListRootsRequest{OrgID: orgA.ID.UInt64(), Limit: 10})
	require.NoError(t, err)
	require.Len(t, list.Rows, 2)
	assert.Equal(t, rb.ID.UInt64(), list.Rows[0].ID.UInt64(), "newest first")
	assert.Equal(t, ra.ID.UInt64(), list.Rows[1].ID.UInt64())

	list, err = provider.ListRoots(ctx, &query.ListRootsRequest{OrgID: orgB.ID.UInt64(), Limit: 10})
	require.NoError(t, err)
	assert.Empty(t, list.Rows)

	list, err = provider.ListRoots(ctx, &query.ListRootsRequest{Platform: true, Limit: 500})
	require.NoError(t, err)
	var platformIDs []uint64
	for _, r := range list.Rows {
		assert.True(t, r.OrgID.IsZero())
		platformIDs = append(platformIDs, r.ID.UInt64())
	}
	assert.Contains(t, platformIDs, pr.ID.UInt64())

	_, err = provider.ListRoots(ctx, &query.ListRootsRequest{Limit: 10})
	assert.ErrorIs(t, err, db.ErrOrgScopeRequired)
	list, err = provider.ListRoots(ctx, &query.ListRootsRequest{AllOrgs: true, Limit: 500})
	require.NoError(t, err)
	var allIDs []uint64
	for _, r := range list.Rows {
		allIDs = append(allIDs, r.ID.UInt64())
	}
	assert.Contains(t, allIDs, pr.ID.UInt64())
	assert.Contains(t, allIDs, ra.ID.UInt64())

	// cursor pagination
	list, err = provider.ListRoots(ctx, &query.ListRootsRequest{OrgID: orgA.ID.UInt64(), Limit: 1, Cursor: query.NewCursor(0)})
	require.NoError(t, err)
	require.Len(t, list.Rows, 1)
	assert.Equal(t, rb.ID.UInt64(), list.Rows[0].ID.UInt64())
	require.True(t, list.HasNextPage)
	next, err := query.ParseCursor(list.Cursor)
	require.NoError(t, err)
	list, err = provider.ListRoots(ctx, &query.ListRootsRequest{OrgID: orgA.ID.UInt64(), Limit: 1, Cursor: next})
	require.NoError(t, err)
	require.Len(t, list.Rows, 1)
	assert.Equal(t, ra.ID.UInt64(), list.Rows[0].ID.UInt64())

	// delete is scoped by org
	n, err := provider.DeleteRoot(ctx, orgB.ID.UInt64(), ra.ID.UInt64())
	require.NoError(t, err)
	assert.EqualValues(t, 0, n)
	n, err = provider.DeleteRoot(ctx, orgA.ID.UInt64(), ra.ID.UInt64())
	require.NoError(t, err)
	assert.EqualValues(t, 1, n)
	n, err = provider.DeleteRoot(ctx, orgA.ID.UInt64(), ra.ID.UInt64())
	require.NoError(t, err)
	assert.EqualValues(t, 0, n)
}
