package query

import (
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/schema"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xdb/xsql"
	"github.com/lib/pq"
)

// RegisterProject returns SQL query to create a project
func RegisterProject(args ...any) (string, string) {
	const key = "RegisterProject"
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		q := schema.ProjectTableInfo.
			InsertInto().
			Returning(schema.ProjectTableInfo.AllColumns())

		q.NewRow().
			Set(schema.Project.ID.Name, nil).
			Set(schema.Project.OrgID.Name, nil).
			Set(schema.Project.Alias.Name, nil).
			Set(schema.Project.Name.Name, nil).
			Set(schema.Project.Description.Name, nil).
			SetExpr(schema.Project.Status.Name, "2").
			SetExpr(schema.Project.CreatedAt.Name, "Now()").
			SetExpr(schema.Project.UpdatedAt.Name, "Now()")
		return q
	})
}

// UpdateProjectRequest defines request for updating a project
type UpdateProjectRequest struct {
	ID          uint64
	Name        string
	Description string
	Status      pb.ItemStatus_Enum
}

// QueryParams returns the query params builder
func (r *UpdateProjectRequest) QueryParams() xdb.QueryParams {
	b := xdb.NewQueryParams("UpdateProject")

	if r.Name != "" {
		b.Set(schema.Project.Name.Position, r.Name)
	}
	if r.Description != "" {
		b.Set(schema.Project.Description.Position, r.Description)
	}
	if r.Status != pb.ItemStatus_Unknown {
		b.Set(schema.Project.Status.Position, r.Status)
	}
	b.AddArgs(r.ID)
	return b
}

// UpdateProject returns SQL query to update a project
func UpdateProject(args ...any) (string, string) {
	p := xdb.GetQueryParams(args...)
	key := p.Name()

	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		q := schema.ProjectTableInfo.
			Update().
			Where(schema.Project.ID.Name+" = ?", nil).
			Returning(schema.ProjectTableInfo.AllColumns())

		if p.IsSet(schema.Project.Name.Position) {
			q.Set(schema.Project.Name.Name, nil)
		}
		if p.IsSet(schema.Project.Description.Position) {
			q.Set(schema.Project.Description.Name, nil)
		}
		if p.IsSet(schema.Project.Status.Position) {
			q.Set(schema.Project.Status.Name, nil)
		}
		q.SetExpr(schema.Project.UpdatedAt.Name, "Now()")
		return q
	})
}

// ListProjectsRequest defines request for list operation on projects
type ListProjectsRequest struct {
	// OrgID specifies the org
	OrgID uint64
	// Status specifies the status of the projects to filter by
	Status pb.ItemStatus_Enum
	// IDs limits the result to the projects with the IDs;
	// used to return only the projects the caller has a grant for
	IDs []uint64
	// Limit specifies maximum number of records to return
	Limit uint32
	// Offset specifies the offset for pagination
	Offset uint32
}

// QueryParams returns the query params builder
func (r *ListProjectsRequest) QueryParams() xdb.QueryParams {
	b := xdb.NewQueryParams("ListProjects")
	if r.OrgID != 0 {
		b.Set(schema.Project.OrgID.Position, r.OrgID)
	}
	if r.Status != pb.ItemStatus_Unknown {
		b.Set(schema.Project.Status.Position, r.Status)
	}
	if r.IDs != nil {
		ids := make([]int64, len(r.IDs))
		for i, id := range r.IDs {
			ids[i] = int64(id)
		}
		b.Set(schema.Project.ID.Position, pq.Array(ids))
	}
	b.SetPage(r.Limit, r.Offset)
	return b
}

// ListProjects returns SQL query
func ListProjects(args ...any) (string, string) {
	p := xdb.GetQueryParams(args...)
	key := p.Name()

	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		q := schema.ProjectTableInfo.
			Select().
			OrderBy("name ASC, id ASC").
			Limit(nil).
			Offset(nil)
		if p.IsSet(schema.Project.OrgID.Position) {
			q.Where(schema.Project.OrgID.Name+" = ?", nil)
		}
		if p.IsSet(schema.Project.Status.Position) {
			q.Where(schema.Project.Status.Name+" = ?", nil)
		}
		if p.IsSet(schema.Project.ID.Position) {
			q.Where(schema.Project.ID.Name+" = ANY(?)", nil)
		}
		return q
	})
}

// GetProjectByAlias returns SQL query to find a project by org and alias
func GetProjectByAlias(args ...any) (string, string) {
	const key = "GetProjectByAlias"
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		return schema.ProjectTableInfo.
			Select().
			Where(schema.Project.OrgID.Name+" = ?", nil).
			Where(schema.Project.Alias.Name+" = ?", nil)
	})
}
