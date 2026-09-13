package query

import (
	"slices"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/schema"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xdb/xsql"
)

// projectIDColumn is the tenancy column shared by membership and invite
const projectIDColumn = "project_id"

// setProjectScope records the project scope in the query params:
// projectID != 0 -> project_id = ?
// scope Org   -> project_id IS NULL
// scope Project  -> project_id IS NOT NULL
// otherwise   -> no filter
func setProjectScope(b *xdb.QueryParamsBuilder, pos uint32, projectID uint64, scope pb.Scope_Enum) {
	switch {
	case projectID != 0:
		b.Set(pos, projectID)
	case scope == pb.Scope_Org:
		b.SetNullColums([]string{projectIDColumn})
	case scope == pb.Scope_Project:
		b.SetEnum(pos, int32(pb.Scope_Project))
	}
}

// whereProjectScope adds the project scope predicate recorded by setProjectScope
func whereProjectScope(q xsql.Builder, p xdb.QueryParams, pos uint32) {
	if slices.Contains(p.GetNullColumns(), projectIDColumn) {
		q.Where(projectIDColumn + " IS NULL")
	} else if _, ok := p.GetEnum(pos); ok {
		q.Where(projectIDColumn + " IS NOT NULL")
	} else if p.IsSet(pos) {
		q.Where(projectIDColumn+" = ?", nil)
	}
}

// AddMember returns SQL query to create or update a membership at its scope
func AddMember(args ...any) (string, string) {
	const key = "AddMember"
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		q := schema.MembershipTableInfo.
			InsertInto().
			Clause(`ON CONFLICT ON CONSTRAINT unique_membership_org_project_user DO UPDATE SET 
	role = EXCLUDED.role`).
			Returning(schema.MembershipTableInfo.AllColumns())
		q.NewRow().
			Set(schema.Membership.ID.Name, nil).
			Set(schema.Membership.OrgID.Name, nil).
			Set(schema.Membership.ProjectID.Name, nil).
			Set(schema.Membership.UserID.Name, nil).
			Set(schema.Membership.Role.Name, nil).
			SetExpr(schema.Membership.CreatedAt.Name, "Now()")
		return q
	})
}

// UpdateMemberRoleRequest defines request to change the role of a membership
// at the given scope: ProjectID 0 is the Org scope membership.
type UpdateMemberRoleRequest struct {
	OrgID     uint64
	ProjectID uint64
	UserID    uint64
	Role      pb.Role_Enum
}

// QueryParams returns the query params builder
func (r *UpdateMemberRoleRequest) QueryParams() xdb.QueryParams {
	b := xdb.NewQueryParams("UpdateMemberRole")
	b.Set(schema.Membership.Role.Position, r.Role)
	b.Set(schema.Membership.OrgID.Position, r.OrgID)
	b.Set(schema.Membership.UserID.Position, r.UserID)
	setProjectScope(b, schema.Membership.ProjectID.Position, r.ProjectID, pb.Scope_Org)
	return b
}

// UpdateMemberRole returns SQL query
func UpdateMemberRole(args ...any) (string, string) {
	p := xdb.GetQueryParams(args...)
	key := p.Name()
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		q := schema.MembershipTableInfo.
			Update().
			Set(schema.Membership.Role.Name, nil).
			Where(schema.Membership.OrgID.Name+" = ?", nil).
			Where(schema.Membership.UserID.Name+" = ?", nil).
			Returning(schema.MembershipTableInfo.AllColumns())
		whereProjectScope(q, p, schema.Membership.ProjectID.Position)
		return q
	})
}

// ListMembershipsRequest defines request to list memberships.
// Without ProjectID and Scope, memberships of all scopes are returned.
type ListMembershipsRequest struct {
	OrgID  uint64
	UserID uint64
	// ProjectID limits the result to the Project scope memberships of the project
	ProjectID uint64
	// Scope limits the result to Org scope (project_id IS NULL) or
	// Project scope (project_id IS NOT NULL) memberships
	Scope     pb.Scope_Enum
	OrgStatus pb.ItemStatus_Enum
	Role      pb.Role_Enum
	// Limit specifies maximum number of records to return
	Limit uint32
	// Offset specifies the offset for pagination
	Offset uint32
}

// QueryParams returns the query params builder
func (r *ListMembershipsRequest) QueryParams() xdb.QueryParams {
	b := xdb.NewQueryParams("ListMemberships")
	if r.UserID != 0 {
		b.Set(schema.MembershipInfo.UserID.Position, r.UserID)
	}
	if r.OrgID != 0 {
		b.Set(schema.MembershipInfo.OrgID.Position, r.OrgID)
	}
	setProjectScope(b, schema.MembershipInfo.ProjectID.Position, r.ProjectID, r.Scope)
	if r.OrgStatus != pb.ItemStatus_Unknown {
		b.Set(schema.MembershipInfo.OrgStatus.Position, r.OrgStatus)
	}
	if r.Role != pb.Role_None {
		b.Set(schema.MembershipInfo.Role.Position, r.Role)
	}
	b.SetPage(r.Limit, r.Offset)
	return b
}

// ListMemberships returns SQL query
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
		whereProjectScope(q, p, schema.MembershipInfo.ProjectID.Position)
		if p.IsSet(schema.MembershipInfo.OrgStatus.Position) {
			q.Where(schema.MembershipInfo.OrgStatus.Name+" = ?", nil)
		}
		if p.IsSet(schema.MembershipInfo.Role.Position) {
			q.Where(schema.MembershipInfo.Role.Name+" = ?", nil)
		}
		return q
	})
}

// DeleteMemberRequest defines request to delete memberships.
// ProjectID deletes the Project scope membership of the project;
// Scope Org deletes the Org scope membership only;
// otherwise memberships of all scopes matching OrgID and UserID are deleted.
type DeleteMemberRequest struct {
	OrgID     uint64
	ProjectID uint64
	UserID    uint64
	Scope     pb.Scope_Enum
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
	setProjectScope(b, schema.Membership.ProjectID.Position, r.ProjectID, r.Scope)
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
		whereProjectScope(q, p, schema.Membership.ProjectID.Position)
		return q
	})
}
