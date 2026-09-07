package query

import (
	"github.com/effective-security/trustyca/internal/db/schema"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xdb/xsql"
)

// CreateInvite returns SQL query to create or update a project invite
func CreateInvite(args ...any) (string, string) {
	const key = "CreateInvite"
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		q := schema.InviteTableInfo.
			InsertInto().
			Clause(`ON CONFLICT (org_id, email) DO UPDATE SET
	inviter_id = EXCLUDED.inviter_id,
	role = EXCLUDED.role`).
			Returning(schema.InviteTableInfo.AllColumns())
		q.NewRow().
			Set(schema.Invite.ID.Name, nil).
			Set(schema.Invite.OrgID.Name, nil).
			Set(schema.Invite.InviterID.Name, nil).
			Set(schema.Invite.Email.Name, nil).
			Set(schema.Invite.Role.Name, nil).
			SetExpr(schema.Invite.CreatedAt.Name, "Now()")
		return q
	})
}

// GetInviteByOrgAndEmail returns SQL query to get an invite by org and email
func GetInviteByOrgAndEmail(args ...any) (string, string) {
	const key = "GetInviteByOrgAndEmail"
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		return schema.InviteTableInfo.
			Select().
			Where(schema.Invite.OrgID.Name+" = ?", nil).
			Where(schema.Invite.Email.Name+" = ?", nil)
	})
}

// GetOrgInvites returns SQL query to list invites for a org
func GetOrgInvites(args ...any) (string, string) {
	const key = "GetOrgInvites"
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		return schema.InviteTableInfo.
			Select().
			Where(schema.Invite.OrgID.Name+" = ?", nil)
	})
}

// GetUserInvites returns SQL query to list invites for a user's email'
func GetUserInvites(args ...any) (string, string) {
	const key = "GetUserInvites"
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		return schema.InviteTableInfo.
			Select().
			Where(schema.Invite.Email.Name+" = ?", nil)
	})
}

// DeleteInviteRequest defines request to delete an invite from a org
type DeleteInviteRequest struct {
	OrgID uint64
	Email string
}

// QueryParams returns the query params builder
func (r *DeleteInviteRequest) QueryParams() xdb.QueryParams {
	b := xdb.NewQueryParams("DeleteInvite")
	if r.OrgID != 0 {
		b.Set(schema.Invite.OrgID.Position, r.OrgID)
	}
	if r.Email != "" {
		b.Set(schema.Invite.Email.Position, r.Email)
	}
	return b
}

// DeleteInvite returns SQL query
func DeleteInvite(args ...any) (string, string) {
	p := xdb.GetQueryParams(args...)
	key := p.Name()

	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		q := schema.InviteTableInfo.
			DeleteFrom()

		if p.IsSet(schema.Invite.OrgID.Position) {
			q.Where(schema.Invite.OrgID.Name+" = ?", nil)
		}
		if p.IsSet(schema.Invite.Email.Position) {
			q.Where(schema.Invite.Email.Name+" = ?", nil)
		}
		return q
	})
}
