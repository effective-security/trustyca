package query

import (
	tschema "github.com/effective-security/xdb/schema"
	"github.com/effective-security/xdb/xsql"
)

// SQL expressions the builders write literally
const (
	exprNow         = "Now()"
	exprEmptyString = "''"
	exprNull        = "NULL"
)

// BuildQueryFunc returns SQL query and name
type BuildQueryFunc func(args ...any) (string, string)

// GetRowByID returns SQL query,
// the first argument is the table info
func GetRowByID(args ...any) (string, string) {
	ti := args[0].(*tschema.TableInfo)
	key := "GetRowByID" + ti.Name
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		return ti.Select().Where("id = $1")
	})
}

// GetRowByColumn returns SQL query,
// the first argument is the table info,
// the second argument is the column name
func GetRowByColumn(args ...any) (string, string) {
	ti := args[0].(*tschema.TableInfo)
	col := args[1].(string)
	key := "GetRowByColumn" + ti.Name + "_" + col
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		return ti.Select().Where(col + " = $1")
	})
}

// DeleteRowByID returns SQL query,
// the first argument is the table info
func DeleteRowByID(args ...any) (string, string) {
	ti := args[0].(*tschema.TableInfo)
	key := "DeleteRowByID" + ti.Name
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		return ti.DeleteFrom().Where("id = $1")
	})
}

// DeleteRowByOrgAndID returns SQL query to delete a row of a CA table by its
// exact org scope and ID: the first argument is the table info, the query
// arguments are the org ID (NULL for the platform, see OrgArg) and the row ID
func DeleteRowByOrgAndID(args ...any) (string, string) {
	ti := args[0].(*tschema.TableInfo)
	key := "DeleteRowByOrgAndID" + ti.Name
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		return ti.DeleteFrom().Where(orgIDColumn + " IS NOT DISTINCT FROM $1").Where("id = $2")
	})
}

// ListAllColumns returns SQL query to list all columns
func ListAllColumns(args ...any) (string, string) {
	ti := args[0].(*tschema.TableInfo)
	key := "ListAllColumns_" + ti.Name
	order := ti.PrimaryKey
	if order != "" {
		key += "_" + order
		order += " ASC"
	}
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		b := ti.Select().Limit(0).Offset(0)
		if order != "" {
			b.OrderBy(order)
		}
		return b
	})
}
