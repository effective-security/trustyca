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
// org_id IS NOT DISTINCT FROM the org (OrgArg).
//
// The CA lists order by id DESC, the events by (created_at, id) DESC, the
// orgs and the projects by (name, id) ASC, and page by offset or with a
// Cursor: the service decodes the cursor of a request with the parser of
// the list's sort key (ParseCursor, ParseTimeCursor, ParseNameCursor) and
// the provider encodes the cursor of the next page from the last row with
// the matching encoder (EncodeCursor, EncodeTimeCursor, EncodeNameCursor).
// A service parses the cursor of its request with ListCursor, which answers
// an invalid token as an invalid argument, and takes the page size from
// Limit, xdb.DefaultPageSize when the request names none.
package query
