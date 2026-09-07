package query

import (
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/schema"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xdb/xsql"
)

func AddMember(args ...any) (string, string) {
	const key = "AddMember"
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		q := schema.MembershipTableInfo.
			InsertInto().
			Clause(`ON CONFLICT (org_id, user_id) DO UPDATE SET 
	role = EXCLUDED.role`).
			Returning(schema.MembershipTableInfo.AllColumns())
		q.NewRow().
			Set(schema.Membership.ID.Name, nil).
			Set(schema.Membership.OrgID.Name, nil).
			Set(schema.Membership.UserID.Name, nil).
			Set(schema.Membership.Role.Name, nil).
			SetExpr(schema.Membership.CreatedAt.Name, "Now()")
		return q
	})
}

func UpdateMemberRole(args ...any) (string, string) {
	const key = "UpdateMemberRole"
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		return schema.MembershipTableInfo.
			Update().
			Set(schema.Membership.Role.Name, nil).
			Where(schema.Membership.OrgID.Name+" = ?", nil).
			Where(schema.Membership.UserID.Name+" = ?", nil).
			Returning(schema.MembershipTableInfo.AllColumns())
	})
}

type ListMembershipsRequest struct {
	OrgID     uint64
	UserID    uint64
	OrgStatus pb.ItemStatus_Enum
	Role      pb.Role_Enum
	// Limit specifies maximum number of records to return
	Limit uint32
	// Offset specifies the offset for pagination
	Offset uint32

	// TODO: not implemented yet
	// Cursor specifies the cursor for pagination
	// Cursor string
}

// QueryParams returns the query params builder
func (r *ListMembershipsRequest) QueryParams() xdb.QueryParams {
	b := xdb.NewQueryParams("ListMemberships")
	if r.OrgID != 0 {
		b.Set(schema.MembershipInfo.OrgID.Position, r.OrgID)
	}
	if r.UserID != 0 {
		b.Set(schema.MembershipInfo.UserID.Position, r.UserID)
	}
	if r.OrgStatus != pb.ItemStatus_Unknown {
		b.Set(schema.MembershipInfo.OrgStatus.Position, r.OrgStatus)
	}
	if r.Role != pb.Role_None {
		b.Set(schema.MembershipInfo.Role.Position, r.Role)
	}
	b.SetPage(r.Limit, r.Offset)
	return b
}

func ListMemberships(args ...any) (string, string) {
	p := xdb.GetQueryParams(args...)
	key := p.Name()
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		q := schema.MembershipInfoTableInfo.
			Select().Limit(nil).Offset(nil)

		if p.IsSet(schema.MembershipInfo.UserID.Position) {
			q.Where(schema.MembershipInfo.UserID.Name+" = ?", nil)
		}
		if p.IsSet(schema.MembershipInfo.OrgID.Position) {
			q.Where(schema.MembershipInfo.OrgID.Name+" = ?", nil)
		}
		if p.IsSet(schema.MembershipInfo.OrgStatus.Position) {
			q.Where(schema.MembershipInfo.OrgStatus.Name+" = ?", nil)
		}
		if p.IsSet(schema.MembershipInfo.Role.Position) {
			q.Where(schema.MembershipInfo.Role.Name+" = ?", nil)
		}
		return q
	})
}

// DeleteMemberRequest defined request to delete a member from a org
type DeleteMemberRequest struct {
	OrgID  uint64
	UserID uint64
}

// QueryParams returns the query params builder
func (r *DeleteMemberRequest) QueryParams() xdb.QueryParams {
	b := xdb.NewQueryParams("DeleteMember")
	if r.OrgID != 0 {
		b.Set(schema.Membership.OrgID.Position, r.OrgID)
	}
	if r.UserID != 0 {
		b.Set(schema.Membership.UserID.Position, r.UserID)
	}
	return b
}

// DeleteMember returns SQL query
func DeleteMember(args ...any) (string, string) {
	p := xdb.GetQueryParams(args...)
	key := p.Name()

	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		q := schema.MembershipTableInfo.
			DeleteFrom()

		if p.IsSet(schema.Membership.OrgID.Position) {
			q.Where(schema.Membership.OrgID.Name+" = ?", nil)
		}
		if p.IsSet(schema.Membership.UserID.Position) {
			q.Where(schema.Membership.UserID.Name+" = ?", nil)
		}
		return q
	})
}
