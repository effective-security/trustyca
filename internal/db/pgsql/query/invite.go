package query

import (
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/schema"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xdb/xsql"
)

// CreateInvite returns SQL query to create or update an invite at its scope
func CreateInvite(args ...any) (string, string) {
	const key = "CreateInvite"
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		q := schema.InviteTableInfo.
			InsertInto().
			Clause(`ON CONFLICT ON CONSTRAINT unique_invite_org_project_email DO UPDATE SET 
	inviter_id = EXCLUDED.inviter_id, 
	role = EXCLUDED.role, 
	expires_at = EXCLUDED.expires_at`).
			Returning(schema.InviteTableInfo.AllColumns())
		q.NewRow().
			Set(schema.Invite.ID.Name, nil).
			Set(schema.Invite.OrgID.Name, nil).
			Set(schema.Invite.ProjectID.Name, nil).
			Set(schema.Invite.InviterID.Name, nil).
			Set(schema.Invite.Email.Name, nil).
			Set(schema.Invite.Role.Name, nil).
			SetExpr(schema.Invite.CreatedAt.Name, "Now()").
			Set(schema.Invite.ExpiresAt.Name, nil)
		return q
	})
}

// GetInviteRequest defines request to get an invite by org, scope and email.
// ProjectID 0 is the Org scope invite.
type GetInviteRequest struct {
	OrgID     uint64
	ProjectID uint64
	Email     string
}

// QueryParams returns the query params builder
func (r *GetInviteRequest) QueryParams() xdb.QueryParams {
	b := xdb.NewQueryParams("GetInvite")
	b.Set(schema.Invite.OrgID.Position, r.OrgID)
	b.Set(schema.Invite.Email.Position, r.Email)
	setProjectScope(b, schema.Invite.ProjectID.Position, r.ProjectID, pb.Scope_Org)
	return b
}

// GetInvite returns SQL query to get an invite by org, scope and email
func GetInvite(args ...any) (string, string) {
	p := xdb.GetQueryParams(args...)
	key := p.Name()
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		q := schema.InviteTableInfo.
			Select().
			Where(schema.Invite.OrgID.Name+" = ?", nil).
			Where(schema.Invite.Email.Name+" = ?", nil)
		whereProjectScope(q, p, schema.Invite.ProjectID.Position)
		return q
	})
}

// GetOrgInvites returns SQL query to list invites of all scopes for an org
func GetOrgInvites(args ...any) (string, string) {
	const key = "GetOrgInvites"
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		return schema.InviteTableInfo.
			Select().
			Where(schema.Invite.OrgID.Name+" = ?", nil)
	})
}

// GetUserInvites returns SQL query to list the pending, not expired invites
// for a user's email
func GetUserInvites(args ...any) (string, string) {
	const key = "GetUserInvites"
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		return schema.InviteTableInfo.
			Select().
			Where(schema.Invite.Email.Name+" = ?", nil).
			Where("(" + schema.Invite.ExpiresAt.Name + " IS NULL OR " + schema.Invite.ExpiresAt.Name + " > Now())")
	})
}

// DeleteInviteRequest defines request to delete invites.
// ProjectID deletes the Project scope invite of the project;
// Scope Org deletes the Org scope invite only;
// otherwise invites of all scopes matching OrgID and Email are deleted.
type DeleteInviteRequest struct {
	OrgID     uint64
	ProjectID uint64
	Email     string
	Scope     pb.Scope_Enum
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
	setProjectScope(b, schema.Invite.ProjectID.Position, r.ProjectID, r.Scope)
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
		whereProjectScope(q, p, schema.Invite.ProjectID.Position)
		return q
	})
}
