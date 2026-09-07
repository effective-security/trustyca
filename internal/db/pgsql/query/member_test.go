package query_test

import (
	"testing"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/internal/db/schema"
)

func Test_MemberQueries(t *testing.T) {
	t.Parallel()

	check(t, []tcase{
		{
			query.ListMemberships, []any{&query.ListMembershipsRequest{UserID: 1, OrgStatus: pb.ItemStatus_Active}},
			`SELECT ` + schema.MembershipInfoTableInfo.AllColumns() + ` 
FROM trustyca.vw_membership_info 
WHERE user_id = $1 AND org_status = $2 
LIMIT $3 
OFFSET $4`,
		},
		{
			query.ListMemberships, []any{&query.ListMembershipsRequest{OrgID: 1, OrgStatus: pb.ItemStatus_Active}},
			`SELECT ` + schema.MembershipInfoTableInfo.AllColumns() + ` 
FROM trustyca.vw_membership_info 
WHERE org_id = $1 AND org_status = $2 
LIMIT $3 
OFFSET $4`,
		},
		{
			query.UpdateMemberRole, nil,
			`UPDATE trustyca.membership 
SET role=$1 
WHERE org_id = $2 AND user_id = $3 
RETURNING ` + schema.MembershipTableInfo.AllColumns(),
		},
		{
			query.AddMember, nil,
			`INSERT INTO trustyca.membership 
( id, org_id, user_id, role, created_at 
) VALUES ( $1, $2, $3, $4, Now() 
) 
ON CONFLICT (org_id, user_id) DO UPDATE SET 
	role = EXCLUDED.role 
RETURNING ` + schema.MembershipTableInfo.AllColumns(),
		},
		{
			query.GetRowByID, []any{&schema.MembershipInfoTableInfo},
			`SELECT ` + schema.MembershipInfoTableInfo.AllColumns() + ` 
FROM trustyca.vw_membership_info 
WHERE id = $1`,
		},
		{
			query.GetRowByColumn, []any{&schema.MembershipInfoTableInfo, "user_id"},
			`SELECT ` + schema.MembershipInfoTableInfo.AllColumns() + ` 
FROM trustyca.vw_membership_info 
WHERE user_id = $1`,
		},
		{
			query.DeleteMember, []any{&query.DeleteMemberRequest{OrgID: 1, UserID: 2}},
			`DELETE FROM trustyca.membership 
WHERE org_id = $1 AND user_id = $2`,
		},
		{
			query.DeleteMember, []any{&query.DeleteMemberRequest{OrgID: 1}},
			`DELETE FROM trustyca.membership 
WHERE org_id = $1`,
		},
		{
			query.DeleteMember, []any{&query.DeleteMemberRequest{UserID: 2}},
			`DELETE FROM trustyca.membership 
WHERE user_id = $1`,
		},
	})
}
