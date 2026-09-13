package query_test

import (
	"testing"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/internal/db/schema"
)

func Test_APIKeysQuery(t *testing.T) {
	t.Parallel()

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
			query.ListAPIKeys, []any{&query.ListAPIKeysRequest{OrgID: 1, ProjectID: 1, Scopes: []string{"scope1", "scope2"}, Limit: 10, Offset: 20}},
			`SELECT ` + schema.APIKeyTableInfo.AllColumns() + ` 
FROM trustyca.apikey 
WHERE org_id = $1 AND project_id = $2 AND scopes @> $3 
ORDER BY created_at DESC, id DESC 
LIMIT $4 
OFFSET $5`,
		},
		{
			query.ListAPIKeys, []any{&query.ListAPIKeysRequest{OrgID: 1, ProjectID: 1, Key: "key123", Status: pb.ItemStatus_Active, Limit: 10, Offset: 20}},
			`SELECT ` + schema.APIKeyTableInfo.AllColumns() + ` 
FROM trustyca.apikey 
WHERE org_id = $1 AND project_id = $2 AND key = $3 AND status = $4 
ORDER BY created_at DESC, id DESC 
LIMIT $5 
OFFSET $6`,
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
