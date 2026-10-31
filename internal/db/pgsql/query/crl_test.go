package query_test

import (
	"github.com/lib/pq"
	"testing"
	"time"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/internal/db/schema"
	"github.com/effective-security/xdb"
	"github.com/stretchr/testify/require"
)

func Test_CrlQuery(t *testing.T) {
	t.Parallel()

	now := time.Now()
	cursor, err := query.ParseCursor(query.EncodeCursor(xdb.NewID(5)))
	require.NoError(t, err)

	check(t, []tcase{
		{
			query.PublishCrl, nil,
			`INSERT INTO trustyca.crl 
( id, org_id, project_id, issuer_id, ikid, crl_number, this_update, next_update, issuer, pem, locations, created_at 
) VALUES ( $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, Now() 
) 
ON CONFLICT ON CONSTRAINT unique_crl_ikid DO UPDATE SET 
	crl_number = EXCLUDED.crl_number, 
	this_update = EXCLUDED.this_update, 
	next_update = EXCLUDED.next_update, 
	issuer = EXCLUDED.issuer, 
	pem = EXCLUDED.pem, 
	locations = EXCLUDED.locations 
RETURNING ` + schema.CrlTableInfo.AllColumns(),
		},
		{
			query.GetCrlsByIKIDs, nil,
			`SELECT ` + schema.CrlTableInfo.AllColumns() + ` 
FROM trustyca.crl 
WHERE ikid = ANY($1)`,
		},
		{
			query.GetCrlByIKID, nil,
			`SELECT ` + schema.CrlTableInfo.AllColumns() + ` 
FROM trustyca.crl 
WHERE ikid = $1`,
		},
		{
			query.DeleteCrl, nil,
			`DELETE FROM trustyca.crl 
WHERE org_id IS NOT DISTINCT FROM $1 AND ikid = $2`,
		},
		{
			// the renewal task: every CRL due before the time
			query.ListCrls, []any{&query.ListCrlsRequest{AllOrgs: true, ExpiringBefore: &now, Limit: 10}},
			`SELECT ` + schema.CrlTableInfo.AllColumns() + ` 
FROM trustyca.crl 
WHERE next_update < $1 
ORDER BY id DESC 
LIMIT $2 
OFFSET $3`,
		},
		{
			query.ListCrls, []any{&query.ListCrlsRequest{OrgID: 1, Scope: pb.Scope_Org, Limit: 10, Cursor: cursor}},
			`SELECT ` + schema.CrlTableInfo.AllColumns() + ` 
FROM trustyca.crl 
WHERE org_id = $1 AND project_id IS NULL AND id < $2 
ORDER BY id DESC 
LIMIT $3`,
		},
		{
			query.ListCrls, []any{&query.ListCrlsRequest{Platform: true, Limit: 10}},
			`SELECT ` + schema.CrlTableInfo.AllColumns() + ` 
FROM trustyca.crl 
WHERE org_id IS NULL 
ORDER BY id DESC 
LIMIT $1 
OFFSET $2`,
		},
	})
}

func Test_CrlStatesQuery(t *testing.T) {
	t.Parallel()

	now := time.Now()
	cursor, err := query.ParseCursor(query.EncodeCursor(xdb.NewID(5)))
	require.NoError(t, err)
	statuses := []pb.IssuerStatus_Enum{pb.IssuerStatus_Active, pb.IssuerStatus_Archived}
	const cols = `id, label, skid, not_after, config, (SELECT next_update FROM trustyca.crl WHERE trustyca.crl.ikid = trustyca.issuer.skid)`

	check(t, []tcase{
		{
			// the projection of the issuers that publish CRLs and the next
			// update of their CRL: the org, a project, the visible projects
			query.ListCrlStates, []any{&query.ListCrlStatesRequest{OrgID: 1, Statuses: statuses, Limit: 10, Cursor: cursor}},
			`SELECT ` + cols + ` 
FROM trustyca.issuer 
WHERE org_id = $1 AND status = ANY($2) AND id < $3 
ORDER BY id DESC 
LIMIT $4`,
		},
		{
			query.ListCrlStates, []any{&query.ListCrlStatesRequest{OrgID: 1, ProjectID: 2, Statuses: statuses, Limit: 10, Cursor: cursor}},
			`SELECT ` + cols + ` 
FROM trustyca.issuer 
WHERE org_id = $1 AND project_id = $2 AND status = ANY($3) AND id < $4 
ORDER BY id DESC 
LIMIT $5`,
		},
		{
			query.ListCrlStates, []any{&query.ListCrlStatesRequest{OrgID: 1, ProjectIDs: []uint64{2}, Statuses: statuses, Limit: 10, Cursor: query.NewCursor(0)}},
			`SELECT ` + cols + ` 
FROM trustyca.issuer 
WHERE org_id = $1 AND (project_id IS NULL OR project_id = ANY($2)) AND status = ANY($3) 
ORDER BY id DESC 
LIMIT $4 
OFFSET $5`,
		},
	})

	// the statuses follow the scope as an integer array
	qp := (&query.ListCrlStatesRequest{OrgID: 1, Statuses: statuses, Limit: 10, Cursor: cursor}).QueryParams()
	require.Equal(t, uint64(1), qp.Args()[0])
	require.Equal(t, pq.Int32Array{2, 3}, qp.Args()[1])

	// the requests are validated
	require.EqualError(t, (&query.ListCrlStatesRequest{Statuses: statuses}).Validate(), "org ID is required")
	require.EqualError(t, (&query.ListCrlStatesRequest{OrgID: 1}).Validate(), "issuer statuses are required")
	require.EqualError(t, (&query.SummaryRequest{}).Validate(), "org ID is required")
	require.EqualError(t, (&query.SummaryRequest{OrgID: 1}).Validate(), "issuer statuses are required")
	require.EqualError(t, (&query.SummaryRequest{OrgID: 1, CrlStatuses: statuses, Expiring: []time.Duration{time.Hour}}).Validate(), "expiry time is required")
	require.NoError(t, (&query.SummaryRequest{OrgID: 1, CrlStatuses: statuses}).Validate())

	// the summary request names the scope of its three reads
	periods := []time.Duration{time.Hour, 2 * time.Hour}
	summary := &query.SummaryRequest{OrgID: 1, ProjectID: 2, ProjectIDs: []uint64{3}, Now: now, Expiring: periods, CrlStatuses: statuses}
	require.Equal(t, &query.CountIssuersRequest{OrgID: 1, ProjectID: 2, ProjectIDs: []uint64{3}}, summary.Issuers())
	require.Equal(t, &query.CountCertificatesRequest{OrgID: 1, ProjectID: 2, ProjectIDs: []uint64{3}, Now: now, Expiring: periods}, summary.Certificates())
	require.Equal(t, &query.ListCrlStatesRequest{OrgID: 1, ProjectID: 2, ProjectIDs: []uint64{3}, Statuses: statuses, Limit: xdb.DefaultPageSize, Cursor: cursor}, summary.CrlStates(cursor))
}
