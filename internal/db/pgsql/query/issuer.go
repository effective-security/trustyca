package query

import (
	"encoding/json"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/schema"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xdb/xsql"
)

// RegisterIssuer returns SQL query to insert an issuer
func RegisterIssuer(args ...any) (string, string) {
	const key = "RegisterIssuer"
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		q := schema.IssuerTableInfo.
			InsertInto().
			Returning(schema.IssuerTableInfo.AllColumns())
		q.NewRow().
			Set(schema.Issuer.ID.Name, nil).
			Set(schema.Issuer.OrgID.Name, nil).
			Set(schema.Issuer.ProjectID.Name, nil).
			Set(schema.Issuer.Label.Name, nil).
			Set(schema.Issuer.Type.Name, nil).
			Set(schema.Issuer.Status.Name, nil).
			Set(schema.Issuer.ParentID.Name, nil).
			Set(schema.Issuer.Skid.Name, nil).
			Set(schema.Issuer.Ikid.Name, nil).
			Set(schema.Issuer.SerialNumber.Name, nil).
			Set(schema.Issuer.Subject.Name, nil).
			Set(schema.Issuer.Issuer.Name, nil).
			Set(schema.Issuer.Sha256.Name, nil).
			Set(schema.Issuer.NotBefore.Name, nil).
			Set(schema.Issuer.NotAfter.Name, nil).
			Set(schema.Issuer.Pem.Name, nil).
			Set(schema.Issuer.ChainPem.Name, nil).
			Set(schema.Issuer.RootPem.Name, nil).
			Set(schema.Issuer.CsrPem.Name, nil).
			Set(schema.Issuer.KeyProvider.Name, nil).
			Set(schema.Issuer.KeyID.Name, nil).
			Set(schema.Issuer.KeyProtected.Name, nil).
			Set(schema.Issuer.Config.Name, nil).
			Set(schema.Issuer.CrlNumber.Name, nil).
			SetExpr(schema.Issuer.CreatedAt.Name, exprNow).
			SetExpr(schema.Issuer.UpdatedAt.Name, exprNow)
		return q
	})
}

// UpdateIssuerRequest defines request to update the lifecycle status or the
// runtime settings of an issuer. The DB layer does not enforce the status
// transitions (Pending -> Active -> Archived -> Destroyed): the service does.
type UpdateIssuerRequest struct {
	ID uint64
	// OrgID is the org the issuer belongs to; zero is the platform scope.
	// An issuer of another scope is not found.
	OrgID uint64
	// Status changes the lifecycle status when set; Destroyed also clears the
	// protected key material, because a destroyed issuer holds no key
	Status pb.IssuerStatus_Enum
	// Config replaces the runtime settings (pb.IssuerConfig) when set
	Config json.RawMessage
}

// QueryParams returns the query params builder
func (r *UpdateIssuerRequest) QueryParams() xdb.QueryParams {
	b := xdb.NewQueryParams("UpdateIssuer")
	if r.Status != pb.IssuerStatus_Unknown {
		b.Set(schema.Issuer.Status.Position, r.Status)
		if r.Status == pb.IssuerStatus_Destroyed {
			addNullColumn(b, schema.Issuer.KeyProtected.Name)
		}
	}
	if len(r.Config) > 0 {
		b.Set(schema.Issuer.Config.Position, string(r.Config))
	}
	b.AddArgs(r.ID, OrgArg(r.OrgID))
	return b
}

// UpdateIssuer returns SQL query to update an issuer
func UpdateIssuer(args ...any) (string, string) {
	p := xdb.GetQueryParams(args...)
	key := p.Name()
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		q := schema.IssuerTableInfo.
			Update().
			Where(schema.Issuer.ID.Name+" = ?", nil).
			Returning(schema.IssuerTableInfo.AllColumns())
		whereOrgIs(q)
		if p.IsSet(schema.Issuer.Status.Position) {
			q.Set(schema.Issuer.Status.Name, nil)
		}
		if isNullColumn(p, schema.Issuer.KeyProtected.Name) {
			q.SetExpr(schema.Issuer.KeyProtected.Name, exprNull)
		}
		if p.IsSet(schema.Issuer.Config.Position) {
			q.Set(schema.Issuer.Config.Name, nil)
		}
		q.SetExpr(schema.Issuer.UpdatedAt.Name, exprNow)
		return q
	})
}

// ActivateIssuer returns SQL query to set the certificate of a Pending
// issuer, clear its CSR and make it Active. The arguments are the certificate
// columns, the Active status, the issuer ID, the Pending status and the org
// of the issuer (NULL for the platform).
func ActivateIssuer(args ...any) (string, string) {
	const key = "ActivateIssuer"
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		return schema.IssuerTableInfo.
			Update().
			Set(schema.Issuer.Skid.Name, nil).
			Set(schema.Issuer.Ikid.Name, nil).
			Set(schema.Issuer.SerialNumber.Name, nil).
			Set(schema.Issuer.Subject.Name, nil).
			Set(schema.Issuer.Issuer.Name, nil).
			Set(schema.Issuer.Sha256.Name, nil).
			Set(schema.Issuer.NotBefore.Name, nil).
			Set(schema.Issuer.NotAfter.Name, nil).
			Set(schema.Issuer.Pem.Name, nil).
			Set(schema.Issuer.ChainPem.Name, nil).
			Set(schema.Issuer.RootPem.Name, nil).
			SetExpr(schema.Issuer.CsrPem.Name, exprEmptyString).
			Set(schema.Issuer.Status.Name, nil).
			SetExpr(schema.Issuer.UpdatedAt.Name, exprNow).
			Where(schema.Issuer.ID.Name+" = ?", nil).
			Where(schema.Issuer.Status.Name+" = ?", nil).
			Where(orgIsExpr, nil).
			Returning(schema.IssuerTableInfo.AllColumns())
	})
}

// SetIssuerCrlNumber returns SQL query to record the number of a published
// CRL on the issuer whose SKID is the CRL's IKID. The number must be greater
// than the current one, so the CRL number of an IKID only grows: the
// arguments are the number, the issuer ID, the IKID and the number.
func SetIssuerCrlNumber(args ...any) (string, string) {
	const key = "SetIssuerCrlNumber"
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		return schema.IssuerTableInfo.
			Update().
			Set(schema.Issuer.CrlNumber.Name, nil).
			Where(schema.Issuer.ID.Name+" = ?", nil).
			Where(schema.Issuer.Skid.Name+" = ?", nil).
			Where(schema.Issuer.CrlNumber.Name+" < ?", nil).
			Returning(schema.IssuerTableInfo.AllColumns())
	})
}

// FindIssuerRequest specifies an issuer by its exact scope and label:
// a zero OrgID is the platform scope, a zero ProjectID the org scope
type FindIssuerRequest struct {
	OrgID     uint64
	ProjectID uint64
	Label     string
}

// QueryParams returns the query params builder
func (r *FindIssuerRequest) QueryParams() xdb.QueryParams {
	b := xdb.NewQueryParams("FindIssuer")
	setTenancy(b, schema.Issuer.OrgID.Position, schema.Issuer.ProjectID.Position, r.OrgID, r.ProjectID)
	b.Set(schema.Issuer.Label.Position, r.Label)
	return b
}

// FindIssuer returns SQL query to find an issuer by scope and label
func FindIssuer(args ...any) (string, string) {
	p := xdb.GetQueryParams(args...)
	key := p.Name()
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		q := schema.IssuerTableInfo.Select()
		whereTenancy(q, p, schema.Issuer.OrgID.Position, schema.Issuer.ProjectID.Position)
		q.Where(schema.Issuer.Label.Name+" = ?", nil)
		return q
	})
}

// GetIssuerBySKID returns SQL query to find an issuer by its Subject Key
// Identifier, which is the IKID of the certificates it issued
func GetIssuerBySKID(args ...any) (string, string) {
	const key = "GetIssuerBySKID"
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		return schema.IssuerTableInfo.
			Select().
			Where(schema.Issuer.Skid.Name+" = ?", nil)
	})
}

// ListIssuersRequest defines request to list issuers, newest first.
// The request names its org scope: OrgID, Platform or AllOrgs; without
// ProjectID and Scope the issuers of every scope of the org are returned.
type ListIssuersRequest struct {
	// OrgID limits the result to the org
	OrgID uint64
	// Platform limits the result to the platform issuers (org_id IS NULL)
	// when OrgID is zero
	Platform bool
	// AllOrgs returns the issuers of every org and the platform when OrgID
	// is zero, for the service's own tasks
	AllOrgs bool
	// ProjectID limits the result to the project
	ProjectID uint64
	// Scope limits the result to Org scope (project_id IS NULL) or
	// Project scope (project_id IS NOT NULL) issuers
	Scope pb.Scope_Enum
	// ProjectIDs limits the result to the org-wide rows and the rows of the
	// projects, for a caller with grants in some projects only; nil applies
	// no project filter and an empty list keeps the org-wide rows. ProjectID
	// and Scope take precedence.
	ProjectIDs []uint64
	// ParentID limits the result to the issuers signed by the parent
	ParentID uint64
	// Status limits the result to the lifecycle status
	Status pb.IssuerStatus_Enum
	// Type limits the result to the authority type
	Type pb.AuthorityType_Enum
	// Limit specifies maximum number of records to return
	Limit uint32
	// Offset specifies the offset for offset pagination
	Offset uint32
	// Cursor specifies the position for cursor pagination
	Cursor Cursor
}

// Validate returns ErrOrgScopeRequired when the request names no org scope
func (r *ListIssuersRequest) Validate() error {
	return checkListScope(r.OrgID, r.Platform, r.AllOrgs)
}

// QueryParams returns the query params builder
func (r *ListIssuersRequest) QueryParams() xdb.QueryParams {
	b := xdb.NewQueryParams("ListIssuers")
	setOrgScope(b, schema.Issuer.OrgID.Position, r.OrgID, r.Platform)
	setProjectScope(b, schema.Issuer.ProjectID.Position, r.ProjectID, r.Scope)
	setVisibleProjects(b, schema.Issuer.ProjectID.Position, r.ProjectIDs)
	if r.ParentID != 0 {
		b.Set(schema.Issuer.ParentID.Position, r.ParentID)
	}
	if r.Status != pb.IssuerStatus_Unknown {
		b.Set(schema.Issuer.Status.Position, r.Status)
	}
	if r.Type != pb.AuthorityType_Unknown {
		b.Set(schema.Issuer.Type.Position, r.Type)
	}
	setPage(b, schema.Issuer.ID.Position, r.Limit, r.Offset, r.Cursor)
	return b
}

// ListIssuers returns SQL query to list issuers
func ListIssuers(args ...any) (string, string) {
	p := xdb.GetQueryParams(args...)
	key := p.Name()
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		q := schema.IssuerTableInfo.Select()
		whereTenancy(q, p, schema.Issuer.OrgID.Position, schema.Issuer.ProjectID.Position)
		if p.IsSet(schema.Issuer.ParentID.Position) {
			q.Where(schema.Issuer.ParentID.Name+" = ?", nil)
		}
		if p.IsSet(schema.Issuer.Status.Position) {
			q.Where(schema.Issuer.Status.Name+" = ?", nil)
		}
		if p.IsSet(schema.Issuer.Type.Position) {
			q.Where(schema.Issuer.Type.Name+" = ?", nil)
		}
		pageByID(q, p)
		return q
	})
}
