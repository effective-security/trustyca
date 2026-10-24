package query

import (
	"time"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/schema"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xdb/xsql"
)

// PublishCrl returns SQL query to store the current CRL of an issuer: the
// CRL of the same IKID is replaced, keeping its row ID, creation time and
// issuer (the IKID identifies the issuer, so they never change)
func PublishCrl(args ...any) (string, string) {
	const key = "PublishCrl"
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		q := schema.CrlTableInfo.
			InsertInto().
			Clause(`ON CONFLICT ON CONSTRAINT unique_crl_ikid DO UPDATE SET 
	crl_number = EXCLUDED.crl_number, 
	this_update = EXCLUDED.this_update, 
	next_update = EXCLUDED.next_update, 
	issuer = EXCLUDED.issuer, 
	pem = EXCLUDED.pem, 
	locations = EXCLUDED.locations`).
			Returning(schema.CrlTableInfo.AllColumns())
		q.NewRow().
			Set(schema.Crl.ID.Name, nil).
			Set(schema.Crl.OrgID.Name, nil).
			Set(schema.Crl.ProjectID.Name, nil).
			Set(schema.Crl.IssuerID.Name, nil).
			Set(schema.Crl.Ikid.Name, nil).
			Set(schema.Crl.CrlNumber.Name, nil).
			Set(schema.Crl.ThisUpdate.Name, nil).
			Set(schema.Crl.NextUpdate.Name, nil).
			Set(schema.Crl.Issuer.Name, nil).
			Set(schema.Crl.Pem.Name, nil).
			Set(schema.Crl.Locations.Name, nil).
			SetExpr(schema.Crl.CreatedAt.Name, exprNow)
		return q
	})
}

// GetCrlByIKID returns SQL query to find the current CRL of an issuer
func GetCrlByIKID(args ...any) (string, string) {
	const key = "GetCrlByIKID"
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		return schema.CrlTableInfo.
			Select().
			Where(schema.Crl.Ikid.Name+" = ?", nil)
	})
}

// GetCrlsByIKIDs returns SQL query to find the current CRLs of the issuers
// with the key identifiers; the argument is the array of IKIDs
func GetCrlsByIKIDs(args ...any) (string, string) {
	const key = "GetCrlsByIKIDs"
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		return schema.CrlTableInfo.
			Select().
			Where(schema.Crl.Ikid.Name+" = ANY(?)", nil)
	})
}

// DeleteCrl returns SQL query to delete the CRL of an issuer by the exact
// org scope (NULL for the platform) and IKID
func DeleteCrl(args ...any) (string, string) {
	const key = "DeleteCrl"
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		return schema.CrlTableInfo.
			DeleteFrom().
			Where(orgIsExpr, nil).
			Where(schema.Crl.Ikid.Name+" = ?", nil)
	})
}

// ListCrlsRequest defines request to list the current CRLs, newest first.
// The request names its org scope: OrgID, Platform or AllOrgs; the CRL
// renewal task lists every org with ExpiringBefore set to now plus the
// renewal period.
type ListCrlsRequest struct {
	// OrgID limits the result to the org
	OrgID uint64
	// Platform limits the result to the platform CRLs (org_id IS NULL) when
	// OrgID is zero
	Platform bool
	// AllOrgs returns the CRLs of every org and the platform when OrgID is
	// zero
	AllOrgs bool
	// ProjectID limits the result to the project
	ProjectID uint64
	// Scope limits the result to Org scope (project_id IS NULL) or
	// Project scope (project_id IS NOT NULL) CRLs
	Scope pb.Scope_Enum
	// ExpiringBefore limits the result to the CRLs whose next update is
	// before the time
	ExpiringBefore *time.Time
	// Limit specifies maximum number of records to return
	Limit uint32
	// Offset specifies the offset for offset pagination
	Offset uint32
	// Cursor specifies the position for cursor pagination
	Cursor Cursor
}

// Validate returns ErrOrgScopeRequired when the request names no org scope
func (r *ListCrlsRequest) Validate() error {
	if err := checkListScope(r.OrgID, r.Platform, r.AllOrgs); err != nil {
		return err
	}
	return r.Cursor.checkKey(keyID)
}

// QueryParams returns the query params builder
func (r *ListCrlsRequest) QueryParams() xdb.QueryParams {
	b := xdb.NewQueryParams("ListCrls")
	setOrgScope(b, schema.Crl.OrgID.Position, r.OrgID, r.Platform)
	setProjectScope(b, schema.Crl.ProjectID.Position, r.ProjectID, r.Scope)
	if r.ExpiringBefore != nil {
		b.Set(schema.Crl.NextUpdate.Position, r.ExpiringBefore.UTC())
	}
	setPage(b, r.Limit, r.Offset, r.Cursor)
	return b
}

// ListCrls returns SQL query to list the current CRLs
func ListCrls(args ...any) (string, string) {
	p := xdb.GetQueryParams(args...)
	key := p.Name()
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		q := schema.CrlTableInfo.Select()
		whereTenancy(q, p, schema.Crl.OrgID.Position, schema.Crl.ProjectID.Position)
		if p.IsSet(schema.Crl.NextUpdate.Position) {
			q.Where(schema.Crl.NextUpdate.Name+" < ?", nil)
		}
		pageByIDDesc(q, p)
		return q
	})
}
