package query_test

import (
	"testing"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/internal/db/schema"
)

func Test_OrgQueries(t *testing.T) {
	t.Parallel()

	check(t, []tcase{
		{
			query.RegisterOrg, nil,
			`INSERT INTO trustyca.org 
( id, alias, name, description, status, created_at 
) VALUES ( $1, $2, $3, $4, 2, Now() 
) 
RETURNING ` + schema.OrgTableInfo.AllColumns(),
		},
		{
			query.ListOrgs, []any{&query.ListOrgsRequest{Limit: 10, Offset: 0}},
			`SELECT ` + schema.OrgTableInfo.AllColumns() + ` 
FROM trustyca.org 
LIMIT $1 
OFFSET $2`,
		},
		{
			query.ListOrgs, []any{&query.ListOrgsRequest{Limit: 10, Offset: 0, Status: pb.ItemStatus_Active}},
			`SELECT ` + schema.OrgTableInfo.AllColumns() + ` 
FROM trustyca.org 
WHERE status = $1 
LIMIT $2 
OFFSET $3`,
		},
		{
			query.GetUserOrgs, []any{1},
			`SELECT ` + schema.OrgTableInfo.AliasedColumns("o", nil) + ` 
FROM membership m LEFT JOIN org o ON (o.id = m.org_id) 
WHERE m.user_id = $1 AND o.status = 2`,
		},
		{
			query.UpdateOrg, []any{&query.UpdateOrgRequest{Name: "Test Org", Description: "Test Description", Status: pb.ItemStatus_Active}},
			`UPDATE trustyca.org 
SET name=$1, description=$2, status=$3 
WHERE id = $4 
RETURNING ` + schema.OrgTableInfo.AllColumns(),
		},
	})
}
