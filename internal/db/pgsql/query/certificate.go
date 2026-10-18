package query

import (
	"time"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/schema"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xdb/xsql"
	"github.com/lib/pq"
)

// RegisterCertificate returns SQL query to insert an issued certificate
func RegisterCertificate(args ...any) (string, string) {
	const key = "RegisterCertificate"
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		q := schema.CertificateTableInfo.
			InsertInto().
			Returning(schema.CertificateTableInfo.AllColumns())
		q.NewRow().
			Set(schema.Certificate.ID.Name, nil).
			Set(schema.Certificate.OrgID.Name, nil).
			Set(schema.Certificate.ProjectID.Name, nil).
			Set(schema.Certificate.Skid.Name, nil).
			Set(schema.Certificate.Ikid.Name, nil).
			Set(schema.Certificate.SerialNumber.Name, nil).
			Set(schema.Certificate.NotBefore.Name, nil).
			Set(schema.Certificate.NotAfter.Name, nil).
			Set(schema.Certificate.Subject.Name, nil).
			Set(schema.Certificate.Issuer.Name, nil).
			Set(schema.Certificate.Sha256.Name, nil).
			Set(schema.Certificate.Profile.Name, nil).
			Set(schema.Certificate.Label.Name, nil).
			Set(schema.Certificate.Locations.Name, nil).
			Set(schema.Certificate.Metadata.Name, nil).
			Set(schema.Certificate.Pem.Name, nil).
			Set(schema.Certificate.IssuersPem.Name, nil).
			Set(schema.Certificate.Status.Name, nil).
			SetExpr(schema.Certificate.CreatedAt.Name, exprNow)
		return q
	})
}

// UpdateCertificateRequest defines request to update the mutable,
// client-provided columns of a certificate. A nil Label, Metadata or
// Locations keeps the current value; an empty one clears it.
type UpdateCertificateRequest struct {
	ID uint64
	// OrgID is the org the certificate belongs to; zero is the platform
	// scope. A certificate of another scope is not found.
	OrgID uint64
	// Label replaces the label when not nil
	Label *string
	// Metadata replaces the client metadata when not nil
	Metadata xdb.Metadata
	// Locations replaces the published locations when not nil
	Locations []string
}

// QueryParams returns the query params builder
func (r *UpdateCertificateRequest) QueryParams() xdb.QueryParams {
	b := xdb.NewQueryParams("UpdateCertificate")
	if r.Label != nil {
		b.Set(schema.Certificate.Label.Position, *r.Label)
	}
	if r.Metadata != nil {
		b.Set(schema.Certificate.Metadata.Position, MetadataArg(r.Metadata))
	}
	if r.Locations != nil {
		b.Set(schema.Certificate.Locations.Position, pq.StringArray(r.Locations))
	}
	b.AddArgs(r.ID, OrgArg(r.OrgID))
	return b
}

// UpdateCertificate returns SQL query to update a certificate
func UpdateCertificate(args ...any) (string, string) {
	p := xdb.GetQueryParams(args...)
	key := p.Name()
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		q := schema.CertificateTableInfo.
			Update().
			Where(schema.Certificate.ID.Name+" = ?", nil).
			Returning(schema.CertificateTableInfo.AllColumns())
		whereOrgIs(q)
		if p.IsSet(schema.Certificate.Label.Position) {
			q.Set(schema.Certificate.Label.Name, nil)
		}
		if p.IsSet(schema.Certificate.Metadata.Position) {
			q.Set(schema.Certificate.Metadata.Name, nil)
		}
		if p.IsSet(schema.Certificate.Locations.Position) {
			q.Set(schema.Certificate.Locations.Name, nil)
		}
		return q
	})
}

// UpdateCertificateStatus returns SQL query to set the status of a
// certificate: the arguments are the status and the ID
func UpdateCertificateStatus(args ...any) (string, string) {
	const key = "UpdateCertificateStatus"
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		return schema.CertificateTableInfo.
			Update().
			Set(schema.Certificate.Status.Name, nil).
			Where(schema.Certificate.ID.Name+" = ?", nil).
			Returning(schema.CertificateTableInfo.AllColumns())
	})
}

// GetCertificateForUpdate returns SQL query to read a certificate by ID and
// exact org scope (NULL for the platform), and lock the row for the rest of
// the transaction
func GetCertificateForUpdate(args ...any) (string, string) {
	const key = "GetCertificateForUpdate"
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		return schema.CertificateTableInfo.
			Select().
			Where(schema.Certificate.ID.Name+" = ?", nil).
			Where(orgIsExpr, nil).
			ForUpdate()
	})
}

// GetCertificateBySha256 returns SQL query to find a certificate by its
// thumbprint
func GetCertificateBySha256(args ...any) (string, string) {
	const key = "GetCertificateBySha256"
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		return schema.CertificateTableInfo.
			Select().
			Where(schema.Certificate.Sha256.Name+" = ?", nil)
	})
}

// GetCertificateByIssuerSerial returns SQL query to find a certificate by
// its issuer key identifier and serial number
func GetCertificateByIssuerSerial(args ...any) (string, string) {
	const key = "GetCertificateByIssuerSerial"
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		return schema.CertificateTableInfo.
			Select().
			Where(schema.Certificate.Ikid.Name+" = ?", nil).
			Where(schema.Certificate.SerialNumber.Name+" = ?", nil)
	})
}

// ListCertificatesRequest defines request to list certificates, newest
// first. The request names its org scope: OrgID, Platform or AllOrgs;
// without ProjectID and Scope the certificates of every scope of the org
// are returned.
type ListCertificatesRequest struct {
	// OrgID limits the result to the org
	OrgID uint64
	// Platform limits the result to the platform certificates (org_id IS
	// NULL) when OrgID is zero
	Platform bool
	// AllOrgs returns the certificates of every org and the platform when
	// OrgID is zero, as the CIS lists them by IKID
	AllOrgs bool
	// ProjectID limits the result to the project
	ProjectID uint64
	// Scope limits the result to Org scope (project_id IS NULL) or
	// Project scope (project_id IS NOT NULL) certificates
	Scope pb.Scope_Enum
	// IKID limits the result to the certificates of the issuer
	IKID string
	// SKID limits the result to the certificates of the subject key
	SKID string
	// Profile limits the result to the profile label
	Profile string
	// Status limits the result to the status
	Status pb.CertificateStatus_Enum
	// ExpiringBefore limits the result to the certificates whose validity
	// ends before the time
	ExpiringBefore *time.Time
	// Limit specifies maximum number of records to return
	Limit uint32
	// Offset specifies the offset for offset pagination
	Offset uint32
	// Cursor specifies the position for cursor pagination
	Cursor Cursor
}

// Validate returns ErrOrgScopeRequired when the request names no org scope
func (r *ListCertificatesRequest) Validate() error {
	return checkListScope(r.OrgID, r.Platform, r.AllOrgs)
}

// QueryParams returns the query params builder
func (r *ListCertificatesRequest) QueryParams() xdb.QueryParams {
	b := xdb.NewQueryParams("ListCertificates")
	setOrgScope(b, schema.Certificate.OrgID.Position, r.OrgID, r.Platform)
	setProjectScope(b, schema.Certificate.ProjectID.Position, r.ProjectID, r.Scope)
	if r.IKID != "" {
		b.Set(schema.Certificate.Ikid.Position, r.IKID)
	}
	if r.SKID != "" {
		b.Set(schema.Certificate.Skid.Position, r.SKID)
	}
	if r.Profile != "" {
		b.Set(schema.Certificate.Profile.Position, r.Profile)
	}
	if r.Status != pb.CertificateStatus_Unknown {
		b.Set(schema.Certificate.Status.Position, r.Status)
	}
	if r.ExpiringBefore != nil {
		b.Set(schema.Certificate.NotAfter.Position, r.ExpiringBefore.UTC())
	}
	setPage(b, schema.Certificate.ID.Position, r.Limit, r.Offset, r.Cursor)
	return b
}

// ListCertificates returns SQL query to list certificates
func ListCertificates(args ...any) (string, string) {
	p := xdb.GetQueryParams(args...)
	key := p.Name()
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		q := schema.CertificateTableInfo.Select()
		whereTenancy(q, p, schema.Certificate.OrgID.Position, schema.Certificate.ProjectID.Position)
		if p.IsSet(schema.Certificate.Ikid.Position) {
			q.Where(schema.Certificate.Ikid.Name+" = ?", nil)
		}
		if p.IsSet(schema.Certificate.Skid.Position) {
			q.Where(schema.Certificate.Skid.Name+" = ?", nil)
		}
		if p.IsSet(schema.Certificate.Profile.Position) {
			q.Where(schema.Certificate.Profile.Name+" = ?", nil)
		}
		if p.IsSet(schema.Certificate.Status.Position) {
			q.Where(schema.Certificate.Status.Name+" = ?", nil)
		}
		if p.IsSet(schema.Certificate.NotAfter.Position) {
			q.Where(schema.Certificate.NotAfter.Name+" < ?", nil)
		}
		pageByID(q, p)
		return q
	})
}
