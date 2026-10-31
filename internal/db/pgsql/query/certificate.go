package query

import (
	"time"

	"github.com/cockroachdb/errors"
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
	// ProjectIDs limits the result to the org-wide rows and the rows of the
	// projects, for a caller with grants in some projects only; nil applies
	// no project filter and an empty list keeps the org-wide rows. ProjectID
	// and Scope take precedence.
	ProjectIDs []uint64
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
	if err := checkListScope(r.OrgID, r.Platform, r.AllOrgs); err != nil {
		return err
	}
	return r.Cursor.checkKey(keyID)
}

// QueryParams returns the query params builder
func (r *ListCertificatesRequest) QueryParams() xdb.QueryParams {
	b := xdb.NewQueryParams("ListCertificates")
	setOrgScope(b, schema.Certificate.OrgID.Position, r.OrgID, r.Platform)
	setProjectScope(b, schema.Certificate.ProjectID.Position, r.ProjectID, r.Scope)
	setVisibleProjects(b, schema.Certificate.ProjectID.Position, r.ProjectIDs)
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
	setPage(b, r.Limit, r.Offset, r.Cursor)
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
		pageByIDDesc(q, p)
		return q
	})
}

// CountCertificatesRequest defines request to count the certificates of an
// org by status, and the Active certificates whose validity ends within
// periods after a time: of the whole org, of one project, or of the
// org-wide scope and the projects of ProjectIDs. The org is required: the
// counts are a tenant's.
type CountCertificatesRequest struct {
	// OrgID is the org whose certificates are counted
	OrgID uint64
	// ProjectID limits the count to the project
	ProjectID uint64
	// ProjectIDs limits the count to the org-wide rows and the rows of the
	// projects, for a caller with grants in some projects only; nil applies
	// no project filter and an empty list keeps the org-wide rows.
	// ProjectID takes precedence.
	ProjectIDs []uint64
	// Now is the start of the expiry periods: a certificate whose validity
	// ended before it is expired, not expiring, whatever its status
	Now time.Time
	// Expiring are the periods after Now within which the Active
	// certificates are counted, ascending; each period counts the
	// certificates of the shorter ones too. Empty counts no expiring
	// certificates.
	Expiring []time.Duration
}

// Validate returns ErrOrgRequired when the request names no org, and an
// error when the periods are not positive and ascending
func (r *CountCertificatesRequest) Validate() error {
	err := checkCountScope(r.OrgID)
	if err != nil {
		return err
	}
	if len(r.Expiring) > 0 && r.Now.IsZero() {
		return errors.New("expiry time is required")
	}
	var prev time.Duration
	for _, within := range r.Expiring {
		if within <= prev {
			return errors.New("expiry periods must be positive and ascending")
		}
		prev = within
	}
	return nil
}

// QueryParams returns the query params builder of CountCertificates
func (r *CountCertificatesRequest) QueryParams() xdb.QueryParams {
	b := xdb.NewQueryParams("CountCertificates")
	r.setScope(b)
	return b
}

// ExpiringParams returns the query params builder of
// CountExpiringCertificates for a period: the Active certificates of the
// scope whose validity ends at or after Now and before Now plus the period
func (r *CountCertificatesRequest) ExpiringParams(within time.Duration) xdb.QueryParams {
	b := xdb.NewQueryParams("CountExpiringCertificates")
	r.setScope(b)
	b.Set(schema.Certificate.Status.Position, pb.CertificateStatus_Active)
	now := r.Now.UTC()
	b.AddArgs(now, now.Add(within))
	return b
}

// setScope records the tenancy of the request
func (r *CountCertificatesRequest) setScope(b *xdb.QueryParamsBuilder) {
	setOrgScope(b, schema.Certificate.OrgID.Position, r.OrgID, false)
	setProjectScope(b, schema.Certificate.ProjectID.Position, r.ProjectID, pb.Scope_Undefined)
	setVisibleProjects(b, schema.Certificate.ProjectID.Position, r.ProjectIDs)
}

// CountCertificates returns SQL query to count the certificates of a scope
// by status: a row per status with certificates, read from the entries of
// idx_certificate_org_project_status_notafter
func CountCertificates(args ...any) (string, string) {
	p := xdb.GetQueryParams(args...)
	key := p.Name()
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		q := schema.CertificateTableInfo.Select(schema.Certificate.Status.Name + ", " + exprCount)
		whereTenancy(q, p, schema.Certificate.OrgID.Position, schema.Certificate.ProjectID.Position)
		q.GroupBy(schema.Certificate.Status.Name)
		return q
	})
}

// CountExpiringCertificates returns SQL query to count the certificates of
// a scope and a status whose validity ends within a period: the arguments
// after the scope are the status, the start and the end of the period. The
// range of a project is served by idx_certificate_org_project_status_notafter.
func CountExpiringCertificates(args ...any) (string, string) {
	p := xdb.GetQueryParams(args...)
	key := p.Name()
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		q := schema.CertificateTableInfo.Select(exprCount)
		whereTenancy(q, p, schema.Certificate.OrgID.Position, schema.Certificate.ProjectID.Position)
		q.Where(schema.Certificate.Status.Name+" = ?", nil)
		q.Where(schema.Certificate.NotAfter.Name+" >= ?", nil)
		q.Where(schema.Certificate.NotAfter.Name+" < ?", nil)
		return q
	})
}

// ExpireCertificatesRequest defines request to mark the Active certificates
// whose validity ended before the time as Expired, a batch at a time. The
// batch is the lowest IDs of the remaining Active certificates: the status
// change removes a row from the set, so the next batch continues without an
// offset (the certificate status task).
type ExpireCertificatesRequest struct {
	// Before is the time the validity ended before, typically now
	Before time.Time
	// Limit is the number of certificates one statement marks
	Limit uint32
}

// Validate returns error if the request is not valid
func (r *ExpireCertificatesRequest) Validate() error {
	if r.Before.IsZero() {
		return errors.New("expiry time is required")
	}
	if r.Limit == 0 {
		return errors.New("limit is required")
	}
	return nil
}

// Args returns the positional arguments of ExpireCertificates: the Expired
// status, the Active status of the updated rows, the Active status of the
// batch, the time and the limit
func (r *ExpireCertificatesRequest) Args() []any {
	return []any{
		pb.CertificateStatus_Expired,
		pb.CertificateStatus_Active,
		pb.CertificateStatus_Active,
		r.Before.UTC(),
		r.Limit,
	}
}

// ExpireCertificates returns SQL query to set the status of a batch of
// Active certificates that expired before a time to Expired: the arguments
// are the Expired status, the Active status of the updated rows, the Active
// status of the batch, the time and the batch limit. The batch subquery is
// evaluated on the snapshot the statement started with, so the status is
// checked again on the updated rows: PostgreSQL rechecks that predicate on
// the current version of a row the statement waited for, and a certificate
// RevokeCertificate revoked meanwhile keeps Revoked.
func ExpireCertificates(args ...any) (string, string) {
	const key = "ExpireCertificates"
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		return schema.CertificateTableInfo.
			Update().
			Set(schema.Certificate.Status.Name, nil).
			Where(schema.Certificate.Status.Name+" = ?", nil).
			Where(schema.Certificate.ID.Name+" IN (SELECT "+schema.Certificate.ID.Name+
				" FROM "+schema.CertificateTableInfo.SchemaName+
				" WHERE "+schema.Certificate.Status.Name+" = ? AND "+schema.Certificate.NotAfter.Name+" < ?"+
				" ORDER BY "+schema.Certificate.ID.Name+" LIMIT ?)", nil, nil, nil)
	})
}

// DeleteExpiredCertificatesRequest defines request to delete the
// certificates of any status whose validity ended before the time, with
// their revocations, a batch at a time (retention). The batch is the lowest
// IDs of the remaining rows, so the next batch continues without an offset.
type DeleteExpiredCertificatesRequest struct {
	// Before is the time the validity ended before: now minus the retention
	// period
	Before time.Time
	// Limit is the number of certificates one statement deletes
	Limit uint32
}

// Validate returns error if the request is not valid
func (r *DeleteExpiredCertificatesRequest) Validate() error {
	if r.Before.IsZero() {
		return errors.New("expiry time is required")
	}
	if r.Limit == 0 {
		return errors.New("limit is required")
	}
	return nil
}

// Args returns the positional arguments of DeleteExpiredCertificates: the
// time and the limit
func (r *DeleteExpiredCertificatesRequest) Args() []any {
	return []any{
		r.Before.UTC(),
		r.Limit,
	}
}

// DeleteExpiredCertificates returns SQL query to delete a batch of
// certificates that expired before a time; the revocations follow by
// cascade. The arguments are the time and the batch limit.
func DeleteExpiredCertificates(args ...any) (string, string) {
	const key = "DeleteExpiredCertificates"
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		return schema.CertificateTableInfo.
			DeleteFrom().
			Where(schema.Certificate.ID.Name+" IN (SELECT "+schema.Certificate.ID.Name+
				" FROM "+schema.CertificateTableInfo.SchemaName+
				" WHERE "+schema.Certificate.NotAfter.Name+" < ?"+
				" ORDER BY "+schema.Certificate.ID.Name+" LIMIT ?)", nil, nil)
	})
}
