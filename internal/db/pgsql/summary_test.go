package pgsql_test

import (
	"database/sql"
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

// Test_SummaryCounts covers the CRL states of the tenant summary, a
// projection of the issuers that publish CRLs and the next update of their
// CRL, and the counts read together at one snapshot
func Test_SummaryCounts(t *testing.T) {
	_, org := setupOwnerAndOrg(t, "Test_SummaryCounts")
	project, err := provider.RegisterProject(ctx, &model.Project{OrgID: org.ID, Name: "Summary"})
	require.NoError(t, err)

	root := testutils.NewTestCA(t, "Summary Root", nil)
	ca := testutils.NewTestCA(t, "Summary L2", root)
	orgIssuer := registerIssuer(t, newTestIssuer(org.ID, xdb.ID(0), "SUM_ORG", ca, pb.AuthorityType_Issuing, xdb.ID(0)))
	projectIssuer := registerIssuer(t, newTestIssuer(org.ID, project.ID, "SUM_PRJ", testutils.NewTestCA(t, "Summary L2 Project", root), pb.AuthorityType_Issuing, xdb.ID(0)))
	destroyed := registerIssuer(t, newTestIssuer(org.ID, xdb.ID(0), "SUM_GONE", testutils.NewTestCA(t, "Summary L2 Destroyed", root), pb.AuthorityType_Issuing, xdb.ID(0)))
	orgID := org.ID.UInt64()
	_, err = provider.UpdateIssuer(ctx, &query.UpdateIssuerRequest{ID: projectIssuer.ID.UInt64(), OrgID: orgID, Status: pb.IssuerStatus_Archived})
	require.NoError(t, err)
	_, err = provider.UpdateIssuer(ctx, &query.UpdateIssuerRequest{ID: destroyed.ID.UInt64(), OrgID: orgID, Status: pb.IssuerStatus_Destroyed})
	require.NoError(t, err)
	now := xdb.Now()
	crl, err := provider.PublishCrl(ctx, &model.Crl{
		OrgID:      org.ID,
		IssuerID:   orgIssuer.ID,
		Ikid:       orgIssuer.Skid,
		CrlNumber:  1,
		ThisUpdate: now,
		NextUpdate: now.Add(48 * time.Hour),
		Issuer:     orgIssuer.Subject,
		Pem:        "crl-1",
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = provider.DeleteCrl(ctx, orgID, orgIssuer.Skid)
	})
	crt := ca.Issue(t, "summary.example.com", time.Now().Add(-time.Hour), time.Now().Add(10*24*time.Hour))
	registerCertificate(t, crt, ca, org.ID, project.ID, "peer", nil)

	statuses := []pb.IssuerStatus_Enum{pb.IssuerStatus_Active, pb.IssuerStatus_Archived}
	list := func(req *query.ListCrlStatesRequest) *model.CrlStateResult {
		t.Helper()
		req.OrgID = orgID
		req.Statuses = statuses
		res, err := provider.ListCrlStates(ctx, req)
		require.NoError(t, err)
		return res
	}
	labels := func(res *model.CrlStateResult) []string {
		var out []string
		for _, row := range res.Rows {
			out = append(out, row.Label)
		}
		return out
	}

	// the issuers that publish CRLs, newest first, with the next update of
	// their CRL and without PEMs; the destroyed issuer is not one of them
	res := list(&query.ListCrlStatesRequest{Limit: 10, Cursor: query.NewCursor(0)})
	assert.Equal(t, []string{"SUM_PRJ", "SUM_ORG"}, labels(res))
	assert.False(t, res.HasNextPage)
	assert.Equal(t, projectIssuer.ID.UInt64(), res.Rows[0].ID.UInt64())
	assert.Equal(t, projectIssuer.Skid, res.Rows[0].Skid)
	assert.True(t, res.Rows[0].NextUpdate.IsZero(), "no CRL published")
	assert.Equal(t, orgIssuer.Skid, res.Rows[1].Skid)
	assert.Equal(t, crl.NextUpdate.UnixMilli(), res.Rows[1].NextUpdate.UnixMilli())
	assert.Equal(t, orgIssuer.NotAfter.UnixMilli(), res.Rows[1].NotAfter.UnixMilli())
	cfg, err := res.Rows[1].GetConfig()
	require.NoError(t, err)
	assert.NotNil(t, cfg)

	// a project, the org-wide rows only, one status, a page at a time
	assert.Equal(t, []string{"SUM_PRJ"}, labels(list(&query.ListCrlStatesRequest{ProjectID: project.ID.UInt64(), Limit: 10, Cursor: query.NewCursor(0)})))
	assert.Equal(t, []string{"SUM_ORG"}, labels(list(&query.ListCrlStatesRequest{ProjectIDs: []uint64{}, Limit: 10, Cursor: query.NewCursor(0)})))
	assert.Equal(t, []string{"SUM_PRJ", "SUM_ORG"}, labels(list(&query.ListCrlStatesRequest{ProjectIDs: []uint64{project.ID.UInt64()}, Limit: 10, Cursor: query.NewCursor(0)})))
	active, err := provider.ListCrlStates(ctx, &query.ListCrlStatesRequest{OrgID: orgID, Statuses: []pb.IssuerStatus_Enum{pb.IssuerStatus_Active}, Limit: 10, Cursor: query.NewCursor(0)})
	require.NoError(t, err)
	assert.Equal(t, []string{"SUM_ORG"}, labels(active))
	first := list(&query.ListCrlStatesRequest{Limit: 1, Cursor: query.NewCursor(0)})
	assert.Equal(t, []string{"SUM_PRJ"}, labels(first))
	require.True(t, first.HasNextPage)
	cursor, err := query.ParseCursor(first.Cursor)
	require.NoError(t, err)
	second := list(&query.ListCrlStatesRequest{Limit: 1, Cursor: cursor})
	assert.Equal(t, []string{"SUM_ORG"}, labels(second))
	assert.False(t, second.HasNextPage)
	_, err = provider.ListCrlStates(ctx, &query.ListCrlStatesRequest{OrgID: orgID})
	assert.EqualError(t, err, "issuer statuses are required")

	// the counts and the states together
	const day = 24 * time.Hour
	summary, err := provider.GetSummaryCounts(ctx, &query.SummaryRequest{
		OrgID:       orgID,
		Now:         time.Now(),
		Expiring:    []time.Duration{7 * day, 30 * day},
		CrlStatuses: statuses,
	})
	require.NoError(t, err)
	assert.Equal(t, model.IssuerCounts{pb.IssuerStatus_Active: 1, pb.IssuerStatus_Archived: 1, pb.IssuerStatus_Destroyed: 1}, summary.Issuers)
	assert.Equal(t, map[pb.CertificateStatus_Enum]uint64{pb.CertificateStatus_Active: 1}, summary.Certificates.ByStatus)
	assert.Equal(t, []uint64{0, 1}, summary.Certificates.Expiring)
	assert.Equal(t, []string{"SUM_PRJ", "SUM_ORG"}, labels(&model.CrlStateResult{Rows: summary.CrlStates}))
	summary, err = provider.GetSummaryCounts(ctx, &query.SummaryRequest{OrgID: orgID, ProjectID: project.ID.UInt64(), CrlStatuses: statuses})
	require.NoError(t, err)
	assert.Equal(t, model.IssuerCounts{pb.IssuerStatus_Archived: 1}, summary.Issuers)
	assert.Empty(t, summary.Certificates.Expiring)
	assert.Equal(t, []string{"SUM_PRJ"}, labels(&model.CrlStateResult{Rows: summary.CrlStates}))
	_, err = provider.GetSummaryCounts(ctx, &query.SummaryRequest{})
	assert.EqualError(t, err, "org ID is required")
}

// Test_SummaryCounts_Snapshot covers the reads at one snapshot: the counts
// of a read-only REPEATABLE READ transaction, the one GetSummaryCounts
// opens, do not see a certificate registered meanwhile, and the
// transaction writes nothing
func Test_SummaryCounts_Snapshot(t *testing.T) {
	_, org := setupOwnerAndOrg(t, "Test_SummaryCounts_Snapshot")
	root := testutils.NewTestCA(t, "Snapshot Root", nil)
	ca := testutils.NewTestCA(t, "Snapshot L2", root)
	registerIssuer(t, newTestIssuer(org.ID, xdb.ID(0), "SNAP_L2", ca, pb.AuthorityType_Issuing, xdb.ID(0)))
	now := time.Now()
	issue := func(cn string) *model.Certificate {
		crt := ca.Issue(t, cn, now.Add(-time.Hour), now.Add(3*24*time.Hour))
		return registerCertificate(t, crt, ca, org.ID, xdb.ID(0), "peer", nil)
	}
	issue("snap-1.example.com")
	req := &query.CountCertificatesRequest{
		OrgID:    org.ID.UInt64(),
		Now:      now,
		Expiring: []time.Duration{7 * 24 * time.Hour},
	}

	tx, err := provider.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	require.NoError(t, err)
	defer func() {
		_ = tx.Close()
	}()
	view, ok := tx.(db.CaDb)
	require.True(t, ok, "the transaction runs the reads of the provider")
	res, err := view.CountCertificates(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, []uint64{1}, res.Expiring)

	// a certificate registered meanwhile is counted outside the snapshot
	// only
	second := issue("snap-2.example.com")
	res, err = view.CountCertificates(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, map[pb.CertificateStatus_Enum]uint64{pb.CertificateStatus_Active: 1}, res.ByStatus)
	assert.Equal(t, []uint64{1}, res.Expiring, "the snapshot of the first statement")
	res, err = provider.CountCertificates(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, []uint64{2}, res.Expiring)

	// the transaction is read-only
	_, err = view.UpdateCertificate(ctx, &query.UpdateCertificateRequest{ID: second.ID.UInt64(), OrgID: org.ID.UInt64(), Label: &second.Label})
	assert.ErrorContains(t, err, "read-only transaction")
	require.NoError(t, tx.Close())
	res, err = provider.CountCertificates(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, []uint64{2}, res.Expiring, "the snapshot is released")
}
