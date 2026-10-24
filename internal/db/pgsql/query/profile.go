package query

import (
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/schema"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xdb/xsql"
)

// RegisterProfile returns SQL query to create a certificate profile, or to
// replace the issuer label, status and config of the profile with the same
// label in the same scope
func RegisterProfile(args ...any) (string, string) {
	const key = "RegisterProfile"
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		q := schema.CertificateProfileTableInfo.
			InsertInto().
			Clause(`ON CONFLICT ON CONSTRAINT unique_certificate_profile_org_project_label DO UPDATE SET 
	issuer_label = EXCLUDED.issuer_label, 
	status = EXCLUDED.status, 
	config = EXCLUDED.config, 
	updated_at = Now()`).
			Returning(schema.CertificateProfileTableInfo.AllColumns())
		q.NewRow().
			Set(schema.CertificateProfile.ID.Name, nil).
			Set(schema.CertificateProfile.OrgID.Name, nil).
			Set(schema.CertificateProfile.ProjectID.Name, nil).
			Set(schema.CertificateProfile.Label.Name, nil).
			Set(schema.CertificateProfile.IssuerLabel.Name, nil).
			Set(schema.CertificateProfile.Status.Name, nil).
			Set(schema.CertificateProfile.Config.Name, nil).
			SetExpr(schema.CertificateProfile.CreatedAt.Name, exprNow).
			SetExpr(schema.CertificateProfile.UpdatedAt.Name, exprNow)
		return q
	})
}

// FindProfileRequest specifies a profile by its exact scope and label:
// a zero OrgID is the platform scope, a zero ProjectID the org scope
type FindProfileRequest struct {
	OrgID     uint64
	ProjectID uint64
	Label     string
}

// QueryParams returns the query params builder
func (r *FindProfileRequest) QueryParams() xdb.QueryParams {
	b := xdb.NewQueryParams("FindProfile")
	setTenancy(b, schema.CertificateProfile.OrgID.Position, schema.CertificateProfile.ProjectID.Position, r.OrgID, r.ProjectID)
	b.Set(schema.CertificateProfile.Label.Position, r.Label)
	return b
}

// FindProfile returns SQL query to find a profile by scope and label
func FindProfile(args ...any) (string, string) {
	p := xdb.GetQueryParams(args...)
	key := p.Name()
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		q := schema.CertificateProfileTableInfo.Select()
		whereTenancy(q, p, schema.CertificateProfile.OrgID.Position, schema.CertificateProfile.ProjectID.Position)
		q.Where(schema.CertificateProfile.Label.Name+" = ?", nil)
		return q
	})
}

// ListProfilesRequest defines request to list certificate profiles, newest
// first. The request names its org scope: OrgID, Platform or AllOrgs;
// without ProjectID and Scope the profiles of every scope of the org are
// returned.
type ListProfilesRequest struct {
	// OrgID limits the result to the org
	OrgID uint64
	// Platform limits the result to the platform profiles (org_id IS NULL)
	// when OrgID is zero
	Platform bool
	// AllOrgs returns the profiles of every org and the platform when OrgID
	// is zero
	AllOrgs bool
	// ProjectID limits the result to the project
	ProjectID uint64
	// Scope limits the result to Org scope (project_id IS NULL) or
	// Project scope (project_id IS NOT NULL) profiles
	Scope pb.Scope_Enum
	// ProjectIDs limits the result to the org-wide rows and the rows of the
	// projects, for a caller with grants in some projects only; nil applies
	// no project filter and an empty list keeps the org-wide rows. ProjectID
	// and Scope take precedence.
	ProjectIDs []uint64
	// IssuerLabel limits the result to the profiles bound to the issuer label
	IssuerLabel string
	// Status limits the result to the status
	Status pb.ItemStatus_Enum
	// Limit specifies maximum number of records to return
	Limit uint32
	// Offset specifies the offset for offset pagination
	Offset uint32
	// Cursor specifies the position for cursor pagination
	Cursor Cursor
}

// Validate returns ErrOrgScopeRequired when the request names no org scope
func (r *ListProfilesRequest) Validate() error {
	if err := checkListScope(r.OrgID, r.Platform, r.AllOrgs); err != nil {
		return err
	}
	return r.Cursor.checkKey(keyID)
}

// QueryParams returns the query params builder
func (r *ListProfilesRequest) QueryParams() xdb.QueryParams {
	b := xdb.NewQueryParams("ListProfiles")
	setOrgScope(b, schema.CertificateProfile.OrgID.Position, r.OrgID, r.Platform)
	setProjectScope(b, schema.CertificateProfile.ProjectID.Position, r.ProjectID, r.Scope)
	setVisibleProjects(b, schema.CertificateProfile.ProjectID.Position, r.ProjectIDs)
	if r.IssuerLabel != "" {
		b.Set(schema.CertificateProfile.IssuerLabel.Position, r.IssuerLabel)
	}
	if r.Status != pb.ItemStatus_Unknown {
		b.Set(schema.CertificateProfile.Status.Position, r.Status)
	}
	setPage(b, r.Limit, r.Offset, r.Cursor)
	return b
}

// ListProfiles returns SQL query to list certificate profiles
func ListProfiles(args ...any) (string, string) {
	p := xdb.GetQueryParams(args...)
	key := p.Name()
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		q := schema.CertificateProfileTableInfo.Select()
		whereTenancy(q, p, schema.CertificateProfile.OrgID.Position, schema.CertificateProfile.ProjectID.Position)
		if p.IsSet(schema.CertificateProfile.IssuerLabel.Position) {
			q.Where(schema.CertificateProfile.IssuerLabel.Name+" = ?", nil)
		}
		if p.IsSet(schema.CertificateProfile.Status.Position) {
			q.Where(schema.CertificateProfile.Status.Name+" = ?", nil)
		}
		pageByIDDesc(q, p)
		return q
	})
}
