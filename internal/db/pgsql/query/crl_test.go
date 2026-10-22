package query_test

import (
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
