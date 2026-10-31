package query

import (
	"slices"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xdb/xsql"
	"github.com/lib/pq"
)

// visibleProjectsFlag marks a list limited to the org-wide rows and the rows
// of the projects of setVisibleProjects
const visibleProjectsFlag int32 = 1

// Tenancy columns shared by the membership, invite and CA tables
const (
	orgIDColumn     = "org_id"
	projectIDColumn = "project_id"
	idColumn        = "id"
)

// orgIsExpr matches the exact org scope of a row: NULL for the platform
const orgIsExpr = orgIDColumn + " IS NOT DISTINCT FROM ?"

// ErrOrgScopeRequired is returned by a list request that names neither an
// org, nor the platform, nor every org: a list of CA rows fails closed
var ErrOrgScopeRequired = errors.New("org scope is required: set OrgID, Platform or AllOrgs")

// ErrOrgRequired is returned by a count request that names no org: the
// counts of the tenant summary are an org's
var ErrOrgRequired = errors.New("org ID is required")

// checkCountScope fails a count request that names no org
func checkCountScope(orgID uint64) error {
	if orgID == 0 {
		return errors.WithStack(ErrOrgRequired)
	}
	return nil
}

// OrgArg returns the org_id argument of an exact scope: a zero org is the
// platform's NULL
func OrgArg(orgID uint64) xdb.ID {
	return xdb.NewID(orgID)
}

// checkListScope fails a list request that does not name its org scope
func checkListScope(orgID uint64, platform, allOrgs bool) error {
	if orgID == 0 && !platform && !allOrgs {
		return errors.WithStack(ErrOrgScopeRequired)
	}
	return nil
}

// whereOrgIs adds the exact org scope predicate of a mutation
func whereOrgIs(q xsql.Builder) {
	q.Where(orgIsExpr, nil)
}

// emptyMetadata is the value of a NOT NULL jsonb metadata column without
// entries
const emptyMetadata = "{}"

// MetadataArg returns the value of a NOT NULL jsonb metadata column:
// xdb.Metadata.Value() returns NULL for an empty map, so an explicit empty
// object is written instead
func MetadataArg(m xdb.Metadata) any {
	if len(m) == 0 {
		return emptyMetadata
	}
	return m
}

// LocationsArg returns the value of a NOT NULL varchar[] locations column:
// pq.StringArray writes a nil slice as NULL, so an empty array is written
// instead
func LocationsArg(locations []string) pq.StringArray {
	if locations == nil {
		return pq.StringArray{}
	}
	return locations
}

// addNullColumn records a column the query filters with IS NULL
func addNullColumn(b *xdb.QueryParamsBuilder, col string) {
	b.SetNullColums(append(b.GetNullColumns(), col))
}

// isNullColumn returns true when the query filters the column with IS NULL
func isNullColumn(p xdb.QueryParams, col string) bool {
	return slices.Contains(p.GetNullColumns(), col)
}

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
		addNullColumn(b, projectIDColumn)
	case scope == pb.Scope_Project:
		b.SetEnum(pos, int32(pb.Scope_Project))
	}
}

// setVisibleProjects records a list limited to the org-wide rows and the
// rows of the projects, for a caller with grants in some projects only:
// project_id IS NULL OR project_id = ANY(?). A nil list records nothing, and
// an exact project scope already set by setProjectScope takes precedence.
func setVisibleProjects(b *xdb.QueryParamsBuilder, pos uint32, projectIDs []uint64) {
	if projectIDs == nil || b.IsSet(pos) || isNullColumn(b, projectIDColumn) {
		return
	}
	ids := make([]int64, len(projectIDs))
	for i, id := range projectIDs {
		ids[i] = int64(id)
	}
	b.Set(pos, pq.Array(ids))
	b.SetFlags(visibleProjectsFlag)
}

// whereProjectScope adds the project scope predicate recorded by
// setProjectScope or setVisibleProjects
func whereProjectScope(q xsql.Builder, p xdb.QueryParams, pos uint32) {
	switch {
	case isNullColumn(p, projectIDColumn):
		q.Where(projectIDColumn + " IS NULL")
	case !p.IsSet(pos):
	case slices.Contains(p.GetFlags(), visibleProjectsFlag):
		q.Where("("+projectIDColumn+" IS NULL OR "+projectIDColumn+" = ANY(?))", nil)
	default:
		if _, ok := p.GetEnum(pos); ok {
			q.Where(projectIDColumn + " IS NOT NULL")
		} else {
			q.Where(projectIDColumn+" = ?", nil)
		}
	}
}

// setOrgScope records the org scope of a CA table, where org_id IS NULL is
// the platform scope:
// orgID != 0 -> org_id = ?
// platform   -> org_id IS NULL
// otherwise  -> no filter, rows of every org and the platform; a list
// request allows it only with AllOrgs (checkListScope)
func setOrgScope(b *xdb.QueryParamsBuilder, pos uint32, orgID uint64, platform bool) {
	switch {
	case orgID != 0:
		b.Set(pos, orgID)
	case platform:
		addNullColumn(b, orgIDColumn)
	}
}

// whereOrgScope adds the org scope predicate recorded by setOrgScope
func whereOrgScope(q xsql.Builder, p xdb.QueryParams, pos uint32) {
	if isNullColumn(p, orgIDColumn) {
		q.Where(orgIDColumn + " IS NULL")
	} else if p.IsSet(pos) {
		q.Where(orgIDColumn+" = ?", nil)
	}
}

// setTenancy records the exact tenancy of a CA row: a zero orgID is the
// platform scope (org_id IS NULL) and a zero projectID the org scope
// (project_id IS NULL)
func setTenancy(b *xdb.QueryParamsBuilder, orgPos, projectPos uint32, orgID, projectID uint64) {
	setOrgScope(b, orgPos, orgID, true)
	setProjectScope(b, projectPos, projectID, pb.Scope_Org)
}

// whereTenancy adds the tenancy predicates recorded by setTenancy, or by
// setOrgScope and setProjectScope
func whereTenancy(q xsql.Builder, p xdb.QueryParams, orgPos, projectPos uint32) {
	whereOrgScope(q, p, orgPos)
	whereProjectScope(q, p, projectPos)
}
