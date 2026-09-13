package query_test

import (
	"testing"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/internal/db/schema"
)

func Test_InviteQueries(t *testing.T) {
	t.Parallel()

	check(t, []tcase{
		{
			query.CreateInvite, nil,
			`INSERT INTO trustyca.invite 
( id, org_id, project_id, inviter_id, email, role, created_at, expires_at 
) VALUES ( $1, $2, $3, $4, $5, $6, Now(), $7 
) 
ON CONFLICT ON CONSTRAINT unique_invite_org_project_email DO UPDATE SET 
	inviter_id = EXCLUDED.inviter_id, 
	role = EXCLUDED.role, 
	expires_at = EXCLUDED.expires_at 
RETURNING ` + schema.InviteTableInfo.AllColumns(),
		},
		{
			query.GetInvite, []any{&query.GetInviteRequest{OrgID: 1, Email: "a@example.com"}},
			`SELECT ` + schema.InviteTableInfo.AllColumns() + ` 
FROM trustyca.invite 
WHERE org_id = $1 AND email = $2 AND project_id IS NULL`,
		},
		{
			query.GetInvite, []any{&query.GetInviteRequest{OrgID: 1, ProjectID: 3, Email: "a@example.com"}},
			`SELECT ` + schema.InviteTableInfo.AllColumns() + ` 
FROM trustyca.invite 
WHERE org_id = $1 AND email = $2 AND project_id = $3`,
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
WHERE email = $1 AND (expires_at IS NULL OR expires_at > Now())`,
		},
		{
			// all scopes
			query.DeleteInvite, []any{&query.DeleteInviteRequest{OrgID: 1, Email: "a@example.com"}},
			`DELETE FROM trustyca.invite 
WHERE org_id = $1 AND email = $2`,
		},
		{
			// Org scope only
			query.DeleteInvite, []any{&query.DeleteInviteRequest{OrgID: 1, Email: "a@example.com", Scope: pb.Scope_Org}},
			`DELETE FROM trustyca.invite 
WHERE org_id = $1 AND email = $2 AND project_id IS NULL`,
		},
		{
			// Project scope of a project
			query.DeleteInvite, []any{&query.DeleteInviteRequest{OrgID: 1, ProjectID: 3, Email: "a@example.com"}},
			`DELETE FROM trustyca.invite 
WHERE org_id = $1 AND email = $2 AND project_id = $3`,
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
