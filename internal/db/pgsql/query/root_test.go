package query_test

import (
	"testing"

	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/internal/db/schema"
	"github.com/effective-security/xdb"
	"github.com/stretchr/testify/require"
)

func Test_RootQuery(t *testing.T) {
	t.Parallel()

	cursor, err := query.ParseCursor(query.EncodeCursor(xdb.NewID(5)))
	require.NoError(t, err)

	check(t, []tcase{
		{
			query.RegisterRoot, nil,
			`INSERT INTO trustyca.root_certificate 
( id, org_id, skid, not_before, not_after, subject, sha256, trust, pem, created_at 
) VALUES ( $1, $2, $3, $4, $5, $6, $7, $8, $9, Now() 
) 
ON CONFLICT ON CONSTRAINT unique_root_certificate_sha256 DO UPDATE SET 
	trust = EXCLUDED.trust 
	WHERE root_certificate.org_id IS NOT DISTINCT FROM EXCLUDED.org_id 
RETURNING ` + schema.RootCertificateTableInfo.AllColumns(),
		},
		{
			query.ListRoots, []any{&query.ListRootsRequest{OrgID: 1, Limit: 10, Offset: 20}},
			`SELECT ` + schema.RootCertificateTableInfo.AllColumns() + ` 
FROM trustyca.root_certificate 
WHERE org_id = $1 
ORDER BY id DESC 
LIMIT $2 
OFFSET $3`,
		},
		{
			query.ListRoots, []any{&query.ListRootsRequest{Platform: true, Limit: 10, Cursor: cursor}},
			`SELECT ` + schema.RootCertificateTableInfo.AllColumns() + ` 
FROM trustyca.root_certificate 
WHERE org_id IS NULL AND id < $1 
ORDER BY id DESC 
LIMIT $2`,
		},
		{
			query.ListRoots, []any{&query.ListRootsRequest{AllOrgs: true, Limit: 10}},
			`SELECT ` + schema.RootCertificateTableInfo.AllColumns() + ` 
FROM trustyca.root_certificate 
ORDER BY id DESC 
LIMIT $1 
OFFSET $2`,
		},
	})
}
