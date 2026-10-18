package query

import (
	"slices"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xdb/xsql"
	"github.com/lib/pq"
)

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

// whereProjectScope adds the project scope predicate recorded by setProjectScope
func whereProjectScope(q xsql.Builder, p xdb.QueryParams, pos uint32) {
	if isNullColumn(p, projectIDColumn) {
		q.Where(projectIDColumn + " IS NULL")
	} else if _, ok := p.GetEnum(pos); ok {
		q.Where(projectIDColumn + " IS NOT NULL")
	} else if p.IsSet(pos) {
		q.Where(projectIDColumn+" = ?", nil)
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
