// Package query builds the SQL of the PostgreSQL provider and defines the
// request structs of its list, find and update methods.
//
// A builder returns the SQL and a stable name under which xsql caches it;
// the variants of a query are keyed by the QueryParams of its request, which
// also carries the positional arguments in the order of the WHERE clauses:
//
//	qp := req.QueryParams()
//	sql, name := query.ListCertificates(qp)
//	err := xdb.ExecuteQueryWithPagination(ctx, db, &result, sql, qp)
//
// Tenancy of the CA tables: a list names its org scope with OrgID, Platform
// (org_id IS NULL) or AllOrgs; a mutation matches the exact scope with
// org_id IS NOT DISTINCT FROM the org (OrgArg). Lists order by id DESC and
// page by offset or with a Cursor (ParseCursor, EncodeCursor).
package query
