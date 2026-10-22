package query

import (
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/schema"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xdb/xsql"
)

// RevokeCertificateRequest defines request to revoke a certificate.
// The revocation copies the issuer, serial number, expiry and tenancy from
// the certificate row, so a CRL is built from the revoked table alone.
type RevokeCertificateRequest struct {
	CertificateID uint64
	// OrgID is the org the certificate belongs to; zero is the platform
	// scope. A certificate of another scope is not found.
	OrgID uint64
	// RevokedAt is the revocation time; zero is now
	RevokedAt time.Time
	// Reason is the RFC 5280 reason code
	Reason pb.ReasonCode_Enum
	// ReasonText is an optional free-form note
	ReasonText string
}

// RegisterRevoked returns SQL query to insert a revocation
func RegisterRevoked(args ...any) (string, string) {
	const key = "RegisterRevoked"
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		q := schema.RevokedTableInfo.
			InsertInto().
			Returning(schema.RevokedTableInfo.AllColumns())
		q.NewRow().
			Set(schema.Revoked.ID.Name, nil).
			Set(schema.Revoked.OrgID.Name, nil).
			Set(schema.Revoked.ProjectID.Name, nil).
			Set(schema.Revoked.CertificateID.Name, nil).
			Set(schema.Revoked.Ikid.Name, nil).
			Set(schema.Revoked.SerialNumber.Name, nil).
			Set(schema.Revoked.NotAfter.Name, nil).
			Set(schema.Revoked.RevokedAt.Name, nil).
			Set(schema.Revoked.Reason.Name, nil).
			Set(schema.Revoked.ReasonText.Name, nil)
		return q
	})
}

// GetRevokedRequest specifies the revocation of a certificate by the
// certificate ID, or by the key identifier of its issuer and its serial
// number, as OCSP and CRL lookups address it. When both are given, both must
// match.
type GetRevokedRequest struct {
	CertificateID uint64
	IKID          string
	SerialNumber  string
}

// Validate returns error if the request identifies no certificate
func (r *GetRevokedRequest) Validate() error {
	if r.CertificateID == 0 && (r.IKID == "" || r.SerialNumber == "") {
		return errors.New("certificate ID, or IKID and serial number, are required")
	}
	return nil
}

// QueryParams returns the query params builder
func (r *GetRevokedRequest) QueryParams() xdb.QueryParams {
	b := xdb.NewQueryParams("GetRevoked")
	if r.CertificateID != 0 {
		b.Set(schema.Revoked.CertificateID.Position, r.CertificateID)
	}
	if r.IKID != "" {
		b.Set(schema.Revoked.Ikid.Position, r.IKID)
		b.Set(schema.Revoked.SerialNumber.Position, r.SerialNumber)
	}
	return b
}

// GetRevoked returns SQL query to find the revocation of a certificate
func GetRevoked(args ...any) (string, string) {
	p := xdb.GetQueryParams(args...)
	key := p.Name()
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		q := schema.RevokedTableInfo.Select()
		if p.IsSet(schema.Revoked.CertificateID.Position) {
			q.Where(schema.Revoked.CertificateID.Name+" = ?", nil)
		}
		if p.IsSet(schema.Revoked.Ikid.Position) {
			q.Where(schema.Revoked.Ikid.Name+" = ?", nil).
				Where(schema.Revoked.SerialNumber.Name+" = ?", nil)
		}
		return q
	})
}

// ListRevokedRequest defines request to list revocations, newest first.
// The request names its org scope: OrgID, Platform or AllOrgs. A CRL is
// built from the revocations of an issuer whose certificate is still valid:
// AllOrgs with IKID and ValidAfter set to the CRL time.
type ListRevokedRequest struct {
	// OrgID limits the result to the org
	OrgID uint64
	// Platform limits the result to the platform rows (org_id IS NULL) when
	// OrgID is zero
	Platform bool
	// AllOrgs returns the revocations of every org and the platform when
	// OrgID is zero
	AllOrgs bool
	// ProjectID limits the result to the project
	ProjectID uint64
	// Scope limits the result to Org scope (project_id IS NULL) or
	// Project scope (project_id IS NOT NULL) rows
	Scope pb.Scope_Enum
	// IKID limits the result to the certificates of the issuer
	IKID string
	// ValidAfter limits the result to the certificates whose validity ends
	// after the time
	ValidAfter *time.Time
	// Limit specifies maximum number of records to return
	Limit uint32
	// Offset specifies the offset for offset pagination
	Offset uint32
	// Cursor specifies the position for cursor pagination
	Cursor Cursor
}

// Validate returns ErrOrgScopeRequired when the request names no org scope
func (r *ListRevokedRequest) Validate() error {
	return checkListScope(r.OrgID, r.Platform, r.AllOrgs)
}

// QueryParams returns the query params builder
func (r *ListRevokedRequest) QueryParams() xdb.QueryParams {
	b := xdb.NewQueryParams("ListRevoked")
	setOrgScope(b, schema.Revoked.OrgID.Position, r.OrgID, r.Platform)
	setProjectScope(b, schema.Revoked.ProjectID.Position, r.ProjectID, r.Scope)
	if r.IKID != "" {
		b.Set(schema.Revoked.Ikid.Position, r.IKID)
	}
	if r.ValidAfter != nil {
		b.Set(schema.Revoked.NotAfter.Position, r.ValidAfter.UTC())
	}
	setPage(b, schema.Revoked.ID.Position, r.Limit, r.Offset, r.Cursor)
	return b
}

// ListRevoked returns SQL query to list revocations
func ListRevoked(args ...any) (string, string) {
	p := xdb.GetQueryParams(args...)
	key := p.Name()
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		q := schema.RevokedTableInfo.Select()
		whereTenancy(q, p, schema.Revoked.OrgID.Position, schema.Revoked.ProjectID.Position)
		if p.IsSet(schema.Revoked.Ikid.Position) {
			q.Where(schema.Revoked.Ikid.Name+" = ?", nil)
		}
		if p.IsSet(schema.Revoked.NotAfter.Position) {
			q.Where(schema.Revoked.NotAfter.Name+" > ?", nil)
		}
		pageByID(q, p)
		return q
	})
}

// ListRevokedCertificatesRequest defines request to list revoked
// certificates with their certificate columns, newest revocation first.
// The request names its org scope: OrgID, Platform or AllOrgs.
type ListRevokedCertificatesRequest struct {
	// OrgID limits the result to the org
	OrgID uint64
	// Platform limits the result to the platform rows (org_id IS NULL) when
	// OrgID is zero
	Platform bool
	// AllOrgs returns the rows of every org and the platform when OrgID is
	// zero
	AllOrgs bool
	// ProjectID limits the result to the project
	ProjectID uint64
	// Scope limits the result to Org scope (project_id IS NULL) or
	// Project scope (project_id IS NOT NULL) rows
	Scope pb.Scope_Enum
	// ProjectIDs limits the result to the org-wide rows and the rows of the
	// projects, for a caller with grants in some projects only; nil applies
	// no project filter and an empty list keeps the org-wide rows. ProjectID
	// and Scope take precedence.
	ProjectIDs []uint64
	// IKID limits the result to the certificates of the issuer
	IKID string
	// Limit specifies maximum number of records to return
	Limit uint32
	// Offset specifies the offset for offset pagination
	Offset uint32
	// Cursor specifies the position for cursor pagination
	Cursor Cursor
}

// Validate returns ErrOrgScopeRequired when the request names no org scope
func (r *ListRevokedCertificatesRequest) Validate() error {
	return checkListScope(r.OrgID, r.Platform, r.AllOrgs)
}

// QueryParams returns the query params builder
func (r *ListRevokedCertificatesRequest) QueryParams() xdb.QueryParams {
	b := xdb.NewQueryParams("ListRevokedCertificates")
	setOrgScope(b, schema.RevokedCertificate.OrgID.Position, r.OrgID, r.Platform)
	setProjectScope(b, schema.RevokedCertificate.ProjectID.Position, r.ProjectID, r.Scope)
	setVisibleProjects(b, schema.RevokedCertificate.ProjectID.Position, r.ProjectIDs)
	if r.IKID != "" {
		b.Set(schema.RevokedCertificate.Ikid.Position, r.IKID)
	}
	setPage(b, schema.RevokedCertificate.ID.Position, r.Limit, r.Offset, r.Cursor)
	return b
}

// ListRevokedCertificates returns SQL query to list revoked certificates
// from the vw_revoked_certificate view
func ListRevokedCertificates(args ...any) (string, string) {
	p := xdb.GetQueryParams(args...)
	key := p.Name()
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		q := schema.RevokedCertificateTableInfo.Select()
		whereTenancy(q, p, schema.RevokedCertificate.OrgID.Position, schema.RevokedCertificate.ProjectID.Position)
		if p.IsSet(schema.RevokedCertificate.Ikid.Position) {
			q.Where(schema.RevokedCertificate.Ikid.Name+" = ?", nil)
		}
		pageByID(q, p)
		return q
	})
}
