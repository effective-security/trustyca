package query

import (
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/schema"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xdb/xsql"
)

// RegisterOrg registers a new org
func RegisterOrg(args ...any) (string, string) {
	const key = "RegisterOrg"
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		q := schema.OrgTableInfo.
			InsertInto().
			Returning(schema.OrgTableInfo.AllColumns())

		q.NewRow().
			Set(schema.Org.ID.Name, nil).
			Set(schema.Org.Alias.Name, nil).
			Set(schema.Org.Name.Name, nil).
			Set(schema.Org.Description.Name, nil).
			SetExpr(schema.Org.Status.Name, "2").
			SetExpr(schema.Org.CreatedAt.Name, exprNow)
		return q
	})
}

// UpdateOrgRequest defined request for updating a org
type UpdateOrgRequest struct {
	ID          uint64
	Status      pb.ItemStatus_Enum
	Name        string
	Description string
}

// UpdateOrgRequest returns the query params builder
func (r *UpdateOrgRequest) QueryParams() xdb.QueryParams {
	b := xdb.NewQueryParams("UpdateOrg")

	if r.Name != "" {
		b.Set(schema.Org.Name.Position, r.Name)
	}
	if r.Description != "" {
		b.Set(schema.Org.Description.Position, r.Description)
	}
	if r.Status != pb.ItemStatus_Unknown {
		b.Set(schema.Org.Status.Position, r.Status)
	}
	b.AddArgs(r.ID)
	return b
}

// UpdateOrg returns SQL query to update a org's name and description
func UpdateOrg(args ...any) (string, string) {
	p := xdb.GetQueryParams(args...)
	key := p.Name()

	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		q := schema.OrgTableInfo.
			Update().
			Where(schema.Org.ID.Name+" = ?", nil).
			Returning(schema.OrgTableInfo.AllColumns())

		if p.IsSet(schema.Org.Name.Position) {
			q.Set(schema.Org.Name.Name, nil)
		}
		if p.IsSet(schema.Org.Description.Position) {
			q.Set(schema.Org.Description.Name, nil)
		}
		if p.IsSet(schema.Org.Status.Position) {
			q.Set(schema.Org.Status.Name, nil)
		}
		return q
	})
}

// ListOrgsRequest defined request for list operation on orgs
type ListOrgsRequest struct {
	// Limit specifies maximum number of records to return
	Limit uint32
	// Offset specifies the offset for offset pagination
	Offset uint32
	// Cursor specifies the position for cursor pagination, decoded by
	// ParseNameCursor
	Cursor Cursor
	// Status specifies the status of the orgs
	Status pb.ItemStatus_Enum
}

// Validate fails a request that carries the cursor of another list
func (r *ListOrgsRequest) Validate() error {
	return r.Cursor.checkKey(keyName)
}

// QueryParams returns the query params builder
func (r *ListOrgsRequest) QueryParams() xdb.QueryParams {
	b := xdb.NewQueryParams("ListOrgs")
	if r.Status != pb.ItemStatus_Unknown {
		b.Set(schema.Org.Status.Position, r.Status)
	}
	setPage(b, r.Limit, r.Offset, r.Cursor)
	return b
}

// ListOrgs returns SQL query: the orgs by name, then by id, paged by
// offset or by a cursor on that key (ParseNameCursor, EncodeNameCursor)
func ListOrgs(args ...any) (string, string) {
	p := xdb.GetQueryParams(args...)
	key := p.Name()

	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		q := schema.OrgTableInfo.Select()
		if p.IsSet(schema.Org.Status.Position) {
			q.Where(schema.Org.Status.Name+" = ?", nil)
		}
		pageBy(q, p, OrderDirectionAsc, schema.Org.Name.Name, schema.Org.ID.Name)
		return q
	})
}

// GetUserOrgs returns SQL query
func GetUserOrgs(args ...any) (string, string) {
	const key = "GetUserOrgs"
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		return schema.OrgTableInfo.Dialect.
			From(schema.MembershipTableInfo.Name+" m").
			Select(schema.OrgTableInfo.AliasedColumns("o", nil)).
			LeftJoin(schema.OrgTableInfo.Name+" o", "o.id = m.org_id").
			Where("m."+schema.Membership.UserID.Name+" = ?", nil).
			Where("o." + schema.Org.Status.Name + " = 2")
	})
}
