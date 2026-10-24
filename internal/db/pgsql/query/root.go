package query

import (
	"github.com/effective-security/trustyca/internal/db/schema"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xdb/xsql"
)

// RegisterRoot returns SQL query to register a trust anchor. Registering the
// same certificate again in the same scope updates its trust; the same
// certificate in another scope conflicts and returns no row.
func RegisterRoot(args ...any) (string, string) {
	const key = "RegisterRoot"
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		q := schema.RootCertificateTableInfo.
			InsertInto().
			Clause(`ON CONFLICT ON CONSTRAINT unique_root_certificate_sha256 DO UPDATE SET 
	trust = EXCLUDED.trust 
	WHERE root_certificate.org_id IS NOT DISTINCT FROM EXCLUDED.org_id`).
			Returning(schema.RootCertificateTableInfo.AllColumns())
		q.NewRow().
			Set(schema.RootCertificate.ID.Name, nil).
			Set(schema.RootCertificate.OrgID.Name, nil).
			Set(schema.RootCertificate.Skid.Name, nil).
			Set(schema.RootCertificate.NotBefore.Name, nil).
			Set(schema.RootCertificate.NotAfter.Name, nil).
			Set(schema.RootCertificate.Subject.Name, nil).
			Set(schema.RootCertificate.Sha256.Name, nil).
			Set(schema.RootCertificate.Trust.Name, nil).
			Set(schema.RootCertificate.Pem.Name, nil).
			SetExpr(schema.RootCertificate.CreatedAt.Name, exprNow)
		return q
	})
}

// ListRootsRequest defines request to list trust anchors, newest first.
// The request names its org scope: OrgID, Platform or AllOrgs.
type ListRootsRequest struct {
	// OrgID limits the result to the org
	OrgID uint64
	// Platform limits the result to the platform roots (org_id IS NULL)
	// when OrgID is zero
	Platform bool
	// AllOrgs returns the roots of every org and the platform when OrgID is
	// zero
	AllOrgs bool
	// Limit specifies maximum number of records to return
	Limit uint32
	// Offset specifies the offset for offset pagination
	Offset uint32
	// Cursor specifies the position for cursor pagination
	Cursor Cursor
}

// Validate returns ErrOrgScopeRequired when the request names no org scope
func (r *ListRootsRequest) Validate() error {
	if err := checkListScope(r.OrgID, r.Platform, r.AllOrgs); err != nil {
		return err
	}
	return r.Cursor.checkKey(keyID)
}

// QueryParams returns the query params builder
func (r *ListRootsRequest) QueryParams() xdb.QueryParams {
	b := xdb.NewQueryParams("ListRoots")
	setOrgScope(b, schema.RootCertificate.OrgID.Position, r.OrgID, r.Platform)
	setPage(b, r.Limit, r.Offset, r.Cursor)
	return b
}

// ListRoots returns SQL query to list trust anchors
func ListRoots(args ...any) (string, string) {
	p := xdb.GetQueryParams(args...)
	key := p.Name()
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		q := schema.RootCertificateTableInfo.Select()
		whereOrgScope(q, p, schema.RootCertificate.OrgID.Position)
		pageByIDDesc(q, p)
		return q
	})
}
