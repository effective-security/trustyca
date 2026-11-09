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

func Test_APIKeysQuery(t *testing.T) {
	t.Parallel()

	at := xdb.Time(time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC))
	cursor, err := query.ParseTimeCursor(query.EncodeTimeCursor(at, xdb.NewID(5)))
	require.NoError(t, err)

	check(t, []tcase{
		{
			query.RegisterAPIKey, nil,
			`INSERT INTO trustyca.apikey 
( id, org_id, project_id, key, secret, label, scopes, metadata, status, expires_at, created_at 
) VALUES ( $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, Now() 
) 
RETURNING ` + schema.APIKeyTableInfo.AllColumns(),
		},
		{
			// the key must hold all the requested scopes
			query.ListAPIKeys, []any{&query.ListAPIKeysRequest{OrgID: 1, ProjectID: 1, Scopes: []string{"scope1", "scope2"}, Limit: 10}},
			`SELECT ` + schema.APIKeyTableInfo.AllColumns() + ` 
FROM trustyca.apikey 
WHERE org_id = $1 AND project_id = $2 AND scopes @> $3 
ORDER BY created_at DESC, id DESC 
LIMIT $4 
OFFSET $5`,
		},
		{
			query.ListAPIKeys, []any{&query.ListAPIKeysRequest{OrgID: 1, ProjectID: 1, Key: "key123", Status: pb.ItemStatus_Active, Limit: 10}},
			`SELECT ` + schema.APIKeyTableInfo.AllColumns() + ` 
FROM trustyca.apikey 
WHERE org_id = $1 AND project_id = $2 AND key = $3 AND status = $4 
ORDER BY created_at DESC, id DESC 
LIMIT $5 
OFFSET $6`,
		},
		{
			// the page after the first continues past its sort key
			query.ListAPIKeys, []any{&query.ListAPIKeysRequest{OrgID: 1, Limit: 10, Cursor: cursor}},
			`SELECT ` + schema.APIKeyTableInfo.AllColumns() + ` 
FROM trustyca.apikey 
WHERE org_id = $1 AND (created_at, id) < ($2, $3) 
ORDER BY created_at DESC, id DESC 
LIMIT $4`,
		},
		{
			query.DeleteAPIKey, nil,
			`DELETE FROM trustyca.apikey 
WHERE org_id = $1 AND id = $2`,
		},
		{
			query.UseAPIKey, nil,
			`UPDATE trustyca.apikey 
SET used_count=used_count+1, used_at=Now() 
WHERE org_id = $1 AND id = $2 
RETURNING ` + schema.APIKeyTableInfo.AllColumns(),
		},
		{
			query.GetAPIKey, nil,
			`SELECT ` + schema.APIKeyTableInfo.AllColumns() + ` 
FROM trustyca.apikey 
WHERE org_id = $1 AND id = $2`,
		},
	})
}
