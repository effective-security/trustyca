package query_test

import (
	"testing"

	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/internal/db/schema"
)

func Test_InviteQueries(t *testing.T) {
	t.Parallel()

	check(t, []tcase{
		{
			query.CreateInvite, nil,
			`INSERT INTO trustyca.invite 
( id, org_id, inviter_id, email, role, created_at 
) VALUES ( $1, $2, $3, $4, $5, Now() 
) 
ON CONFLICT (org_id, email) DO UPDATE SET
	inviter_id = EXCLUDED.inviter_id,
	role = EXCLUDED.role 
RETURNING ` + schema.InviteTableInfo.AllColumns(),
		},
		{
			query.GetInviteByOrgAndEmail, nil,
			`SELECT ` + schema.InviteTableInfo.AllColumns() + ` 
FROM trustyca.invite 
WHERE org_id = $1 AND email = $2`,
		},
		{
			query.GetOrgInvites, nil,
			`SELECT ` + schema.InviteTableInfo.AllColumns() + ` 
FROM trustyca.invite 
WHERE org_id = $1`,
		},
		{
			query.GetUserInvites, nil,
			`SELECT ` + schema.InviteTableInfo.AllColumns() + ` 
FROM trustyca.invite 
WHERE email = $1`,
		},
		{
			query.DeleteInvite, []any{&query.DeleteInviteRequest{OrgID: 1, Email: "a@example.com"}},
			`DELETE FROM trustyca.invite 
WHERE org_id = $1 AND email = $2`,
		},
		{
			query.DeleteInvite, []any{&query.DeleteInviteRequest{OrgID: 1}},
			`DELETE FROM trustyca.invite 
WHERE org_id = $1`,
		},
		{
			query.DeleteInvite, []any{&query.DeleteInviteRequest{Email: "a@example.com"}},
			`DELETE FROM trustyca.invite 
WHERE email = $1`,
		},
	})
}
