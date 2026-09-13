// DO NOT EDIT!
// This file is MACHINE GENERATED
// DB: trustycadb

package model

import (
	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/schema"
	"github.com/effective-security/xdb"
	xdbschema "github.com/effective-security/xdb/schema"
	"github.com/effective-security/xdb/xsql"
	"github.com/lib/pq"
)

// Dialect provides Dialect for trustycadb
var Dialect = xsql.Postgres

// APIKey represents one row from table 'trustyca.apikey'.
// Primary key: id
// Indexes:
//
//	apikey_key: UNIQUE [key]
//	apikey_pkey: PRIMARY UNIQUE [id]
//	idx_apikey_org_project: [org_id,project_id]
type APIKey struct {
	// ID represents 'id' column of 'bigint'
	ID xdb.ID `db:"id,int8,index,primary" json:",omitempty"`
	// OrgID represents 'org_id' column of 'bigint'
	OrgID xdb.ID `db:"org_id,int8,index,fk:trustyca.project.id" json:",omitempty"`
	// ProjectID represents 'project_id' column of 'bigint'
	ProjectID xdb.ID `db:"project_id,int8,null,index,fk:trustyca.project.id" json:",omitempty"`
	// Key represents 'key' column of 'character varying'
	Key string `db:"key,varchar,max:128,index" json:",omitempty"`
	// Secret represents 'secret' column of 'character varying'
	Secret string `db:"secret,varchar,max:128" json:",omitempty"`
	// Label represents 'label' column of 'character varying'
	Label string `db:"label,varchar,max:260" json:",omitempty"`
	// Scopes represents 'scopes' column of 'ARRAY'
	Scopes pq.StringArray `db:"scopes,_varchar" json:",omitempty"`
	// Metadata represents 'metadata' column of 'jsonb'
	Metadata xdb.Metadata `db:"metadata,jsonb,null" json:",omitempty"`
	// Status represents 'status' column of 'integer'
	Status pb.ItemStatus_Enum `db:"status,int4" json:",omitempty"`
	// CreatedAt represents 'created_at' column of 'timestamp with time zone'
	CreatedAt xdb.Time `db:"created_at,timestamptz" json:",omitempty"`
	// ExpiresAt represents 'expires_at' column of 'timestamp with time zone'
	ExpiresAt xdb.Time `db:"expires_at,timestamptz,null" json:",omitempty"`
	// UsedAt represents 'used_at' column of 'timestamp with time zone'
	UsedAt xdb.Time `db:"used_at,timestamptz,null" json:",omitempty"`
	// UsedCount represents 'used_count' column of 'integer'
	UsedCount uint32 `db:"used_count,int4" json:",omitempty"`
}

// ScanRow scans one row for apikey.
func (m *APIKey) ScanRow(rows xdb.Row) error {
	err := rows.Scan(
		&m.ID,
		&m.OrgID,
		&m.ProjectID,
		&m.Key,
		&m.Secret,
		&m.Label,
		&m.Scopes,
		&m.Metadata,
		&m.Status,
		&m.CreatedAt,
		&m.ExpiresAt,
		&m.UsedAt,
		&m.UsedCount,
	)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

type APIKeySlice []*APIKey
type APIKeyResult struct {
	Rows        APIKeySlice
	NextOffset  uint32
	HasNextPage bool
	Cursor      string
}

func (p *APIKeyResult) SetResult(rows []*APIKey, hasNextPage bool, nextOffset uint32) {
	p.Rows = rows
	p.NextOffset = nextOffset
	p.HasNextPage = hasNextPage
}

func (p *APIKeyResult) SetResultWithCursor(rows []*APIKey, hasNextPage bool, cursor func(lastRow *APIKey) string) {
	p.Rows = rows
	p.HasNextPage = hasNextPage
	if hasNextPage && len(rows) > 0 {
		p.Cursor = cursor(rows[len(rows)-1])
	}
}

func (p *APIKeyResult) GetTableInfo() *xdbschema.TableInfo {
	return &schema.APIKeyTableInfo
}

// Certificate represents one row from table 'trustyca.certificate'.
// Primary key: id
// Indexes:
//
//	certificate_pkey: PRIMARY UNIQUE [id]
//	idx_certificate_ikid_id_desc: [ikid,id]
//	idx_certificate_org_project_id_desc: [project_id,id,org_id]
//	idx_certificate_org_project_notafter: [not_after,org_id,project_id]
//	idx_certificate_skid: [skid]
//	unique_certificate_ikid_serial: UNIQUE [serial_number,ikid]
//	unique_certificate_sha256: UNIQUE [sha256]
type Certificate struct {
	// ID represents 'id' column of 'bigint'
	ID xdb.ID `db:"id,int8,index,primary" json:",omitempty"`
	// OrgID represents 'org_id' column of 'bigint'
	OrgID xdb.ID `db:"org_id,int8,null,index" json:",omitempty"`
	// ProjectID represents 'project_id' column of 'bigint'
	ProjectID xdb.ID `db:"project_id,int8,null,index" json:",omitempty"`
	// Skid represents 'skid' column of 'character varying'
	Skid string `db:"skid,varchar,max:64,index" json:",omitempty"`
	// Ikid represents 'ikid' column of 'character varying'
	Ikid string `db:"ikid,varchar,max:64,index" json:",omitempty"`
	// SerialNumber represents 'serial_number' column of 'character varying'
	SerialNumber string `db:"serial_number,varchar,max:64,index" json:",omitempty"`
	// NotBefore represents 'not_before' column of 'timestamp with time zone'
	NotBefore xdb.Time `db:"not_before,timestamptz" json:",omitempty"`
	// NotAfter represents 'not_after' column of 'timestamp with time zone'
	NotAfter xdb.Time `db:"not_after,timestamptz,index" json:",omitempty"`
	// Subject represents 'subject' column of 'character varying'
	Subject string `db:"subject,varchar,max:260" json:",omitempty"`
	// Issuer represents 'issuer' column of 'character varying'
	Issuer string `db:"issuer,varchar,max:260" json:",omitempty"`
	// Sha256 represents 'sha256' column of 'character varying'
	Sha256 string `db:"sha256,varchar,max:64,index" json:",omitempty"`
	// Profile represents 'profile' column of 'character varying'
	Profile string `db:"profile,varchar,max:64" json:",omitempty"`
	// Label represents 'label' column of 'character varying'
	Label string `db:"label,varchar,max:260" json:",omitempty"`
	// Locations represents 'locations' column of 'ARRAY'
	Locations pq.StringArray `db:"locations,_varchar" json:",omitempty"`
	// Metadata represents 'metadata' column of 'jsonb'
	Metadata xdb.Metadata `db:"metadata,jsonb" json:",omitempty"`
	// Pem represents 'pem' column of 'text'
	Pem string `db:"pem,text" json:",omitempty"`
	// IssuersPem represents 'issuers_pem' column of 'text'
	IssuersPem string `db:"issuers_pem,text" json:",omitempty"`
	// Status represents 'status' column of 'integer'
	Status pb.CertificateStatus_Enum `db:"status,int4" json:",omitempty"`
	// CreatedAt represents 'created_at' column of 'timestamp with time zone'
	CreatedAt xdb.Time `db:"created_at,timestamptz" json:",omitempty"`
}

// ScanRow scans one row for certificate.
func (m *Certificate) ScanRow(rows xdb.Row) error {
	err := rows.Scan(
		&m.ID,
		&m.OrgID,
		&m.ProjectID,
		&m.Skid,
		&m.Ikid,
		&m.SerialNumber,
		&m.NotBefore,
		&m.NotAfter,
		&m.Subject,
		&m.Issuer,
		&m.Sha256,
		&m.Profile,
		&m.Label,
		&m.Locations,
		&m.Metadata,
		&m.Pem,
		&m.IssuersPem,
		&m.Status,
		&m.CreatedAt,
	)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

type CertificateSlice []*Certificate
type CertificateResult struct {
	Rows        CertificateSlice
	NextOffset  uint32
	HasNextPage bool
	Cursor      string
}

func (p *CertificateResult) SetResult(rows []*Certificate, hasNextPage bool, nextOffset uint32) {
	p.Rows = rows
	p.NextOffset = nextOffset
	p.HasNextPage = hasNextPage
}

func (p *CertificateResult) SetResultWithCursor(rows []*Certificate, hasNextPage bool, cursor func(lastRow *Certificate) string) {
	p.Rows = rows
	p.HasNextPage = hasNextPage
	if hasNextPage && len(rows) > 0 {
		p.Cursor = cursor(rows[len(rows)-1])
	}
}

func (p *CertificateResult) GetTableInfo() *xdbschema.TableInfo {
	return &schema.CertificateTableInfo
}

// CertificateProfile represents one row from table 'trustyca.certificate_profile'.
// Primary key: id
// Indexes:
//
//	certificate_profile_pkey: PRIMARY UNIQUE [id]
//	idx_certificate_profile_org_issuer: [org_id,issuer_label]
//	unique_certificate_profile_org_project_label: UNIQUE [org_id,project_id,label]
type CertificateProfile struct {
	// ID represents 'id' column of 'bigint'
	ID xdb.ID `db:"id,int8,index,primary" json:",omitempty"`
	// OrgID represents 'org_id' column of 'bigint'
	OrgID xdb.ID `db:"org_id,int8,null,index" json:",omitempty"`
	// ProjectID represents 'project_id' column of 'bigint'
	ProjectID xdb.ID `db:"project_id,int8,null,index" json:",omitempty"`
	// Label represents 'label' column of 'character varying'
	Label string `db:"label,varchar,max:64,index" json:",omitempty"`
	// IssuerLabel represents 'issuer_label' column of 'character varying'
	IssuerLabel string `db:"issuer_label,varchar,max:64,index" json:",omitempty"`
	// Status represents 'status' column of 'integer'
	Status pb.ItemStatus_Enum `db:"status,int4" json:",omitempty"`
	// Config represents 'config' column of 'jsonb'
	Config xdb.NULLString `db:"config,jsonb" json:",omitempty"`
	// CreatedAt represents 'created_at' column of 'timestamp with time zone'
	CreatedAt xdb.Time `db:"created_at,timestamptz" json:",omitempty"`
	// UpdatedAt represents 'updated_at' column of 'timestamp with time zone'
	UpdatedAt xdb.Time `db:"updated_at,timestamptz" json:",omitempty"`
}

// ScanRow scans one row for certificate_profile.
func (m *CertificateProfile) ScanRow(rows xdb.Row) error {
	err := rows.Scan(
		&m.ID,
		&m.OrgID,
		&m.ProjectID,
		&m.Label,
		&m.IssuerLabel,
		&m.Status,
		&m.Config,
		&m.CreatedAt,
		&m.UpdatedAt,
	)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

type CertificateProfileSlice []*CertificateProfile
type CertificateProfileResult struct {
	Rows        CertificateProfileSlice
	NextOffset  uint32
	HasNextPage bool
	Cursor      string
}

func (p *CertificateProfileResult) SetResult(rows []*CertificateProfile, hasNextPage bool, nextOffset uint32) {
	p.Rows = rows
	p.NextOffset = nextOffset
	p.HasNextPage = hasNextPage
}

func (p *CertificateProfileResult) SetResultWithCursor(rows []*CertificateProfile, hasNextPage bool, cursor func(lastRow *CertificateProfile) string) {
	p.Rows = rows
	p.HasNextPage = hasNextPage
	if hasNextPage && len(rows) > 0 {
		p.Cursor = cursor(rows[len(rows)-1])
	}
}

func (p *CertificateProfileResult) GetTableInfo() *xdbschema.TableInfo {
	return &schema.CertificateProfileTableInfo
}

// Crl represents one row from table 'trustyca.crl'.
// Primary key: id
// Indexes:
//
//	crl_pkey: PRIMARY UNIQUE [id]
//	idx_crl_next_update: [next_update]
//	unique_crl_ikid: UNIQUE [ikid]
type Crl struct {
	// ID represents 'id' column of 'bigint'
	ID xdb.ID `db:"id,int8,index,primary" json:",omitempty"`
	// OrgID represents 'org_id' column of 'bigint'
	OrgID xdb.ID `db:"org_id,int8,null" json:",omitempty"`
	// ProjectID represents 'project_id' column of 'bigint'
	ProjectID xdb.ID `db:"project_id,int8,null" json:",omitempty"`
	// IssuerID represents 'issuer_id' column of 'bigint'
	IssuerID xdb.ID `db:"issuer_id,int8,fk:trustyca.issuer.id" json:",omitempty"`
	// Ikid represents 'ikid' column of 'character varying'
	Ikid string `db:"ikid,varchar,max:64,index" json:",omitempty"`
	// CrlNumber represents 'crl_number' column of 'bigint'
	CrlNumber int64 `db:"crl_number,int8" json:",omitempty"`
	// ThisUpdate represents 'this_update' column of 'timestamp with time zone'
	ThisUpdate xdb.Time `db:"this_update,timestamptz" json:",omitempty"`
	// NextUpdate represents 'next_update' column of 'timestamp with time zone'
	NextUpdate xdb.Time `db:"next_update,timestamptz,index" json:",omitempty"`
	// Issuer represents 'issuer' column of 'character varying'
	Issuer string `db:"issuer,varchar,max:260" json:",omitempty"`
	// Pem represents 'pem' column of 'text'
	Pem string `db:"pem,text" json:",omitempty"`
	// Locations represents 'locations' column of 'ARRAY'
	Locations pq.StringArray `db:"locations,_varchar" json:",omitempty"`
	// CreatedAt represents 'created_at' column of 'timestamp with time zone'
	CreatedAt xdb.Time `db:"created_at,timestamptz" json:",omitempty"`
}

// ScanRow scans one row for crl.
func (m *Crl) ScanRow(rows xdb.Row) error {
	err := rows.Scan(
		&m.ID,
		&m.OrgID,
		&m.ProjectID,
		&m.IssuerID,
		&m.Ikid,
		&m.CrlNumber,
		&m.ThisUpdate,
		&m.NextUpdate,
		&m.Issuer,
		&m.Pem,
		&m.Locations,
		&m.CreatedAt,
	)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

type CrlSlice []*Crl
type CrlResult struct {
	Rows        CrlSlice
	NextOffset  uint32
	HasNextPage bool
	Cursor      string
}

func (p *CrlResult) SetResult(rows []*Crl, hasNextPage bool, nextOffset uint32) {
	p.Rows = rows
	p.NextOffset = nextOffset
	p.HasNextPage = hasNextPage
}

func (p *CrlResult) SetResultWithCursor(rows []*Crl, hasNextPage bool, cursor func(lastRow *Crl) string) {
	p.Rows = rows
	p.HasNextPage = hasNextPage
	if hasNextPage && len(rows) > 0 {
		p.Cursor = cursor(rows[len(rows)-1])
	}
}

func (p *CrlResult) GetTableInfo() *xdbschema.TableInfo {
	return &schema.CrlTableInfo
}

// Event represents one row from table 'trustyca.event'.
// Primary key: id
// Indexes:
//
//	event_pkey: PRIMARY UNIQUE [id]
//	idx_event_email: [email]
//	idx_event_org_created_id_desc: [id,org_id,created_at]
//	idx_event_org_id: [org_id]
//	idx_event_org_project_created_id_desc: [org_id,id,project_id,created_at]
//	idx_event_org_ref_id: [org_id,ref_id]
//	idx_event_type: [type]
type Event struct {
	// ID represents 'id' column of 'bigint'
	ID xdb.ID `db:"id,int8,index,primary" json:",omitempty"`
	// OrgID represents 'org_id' column of 'bigint'
	OrgID xdb.ID `db:"org_id,int8,null,index,fk:trustyca.org.id" json:",omitempty"`
	// ProjectID represents 'project_id' column of 'bigint'
	ProjectID xdb.ID `db:"project_id,int8,null,index,fk:trustyca.project.id" json:",omitempty"`
	// Type represents 'type' column of 'integer'
	Type pb.EventType_Enum `db:"type,int4,index" json:",omitempty"`
	// Title represents 'title' column of 'character varying'
	Title string `db:"title,varchar,max:256" json:",omitempty"`
	// Description represents 'description' column of 'text'
	Description xdb.NULLString `db:"description,text,null" json:",omitempty"`
	// Metadata represents 'metadata' column of 'jsonb'
	Metadata xdb.Metadata `db:"metadata,jsonb" json:",omitempty"`
	// ReferenceID represents 'ref_id' column of 'bigint'
	ReferenceID xdb.ID `db:"ref_id,int8,null,index" json:",omitempty"`
	// Email represents 'email' column of 'character varying'
	Email xdb.NULLString `db:"email,varchar,max:160,null,index" json:",omitempty"`
	// Source represents 'source' column of 'character varying'
	Source xdb.NULLString `db:"source,varchar,max:256,null" json:",omitempty"`
	// CreatedAt represents 'created_at' column of 'timestamp with time zone'
	CreatedAt xdb.Time `db:"created_at,timestamptz,index" json:",omitempty"`
}

// ScanRow scans one row for event.
func (m *Event) ScanRow(rows xdb.Row) error {
	err := rows.Scan(
		&m.ID,
		&m.OrgID,
		&m.ProjectID,
		&m.Type,
		&m.Title,
		&m.Description,
		&m.Metadata,
		&m.ReferenceID,
		&m.Email,
		&m.Source,
		&m.CreatedAt,
	)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

type EventSlice []*Event
type EventResult struct {
	Rows        EventSlice
	NextOffset  uint32
	HasNextPage bool
	Cursor      string
}

func (p *EventResult) SetResult(rows []*Event, hasNextPage bool, nextOffset uint32) {
	p.Rows = rows
	p.NextOffset = nextOffset
	p.HasNextPage = hasNextPage
}

func (p *EventResult) SetResultWithCursor(rows []*Event, hasNextPage bool, cursor func(lastRow *Event) string) {
	p.Rows = rows
	p.HasNextPage = hasNextPage
	if hasNextPage && len(rows) > 0 {
		p.Cursor = cursor(rows[len(rows)-1])
	}
}

func (p *EventResult) GetTableInfo() *xdbschema.TableInfo {
	return &schema.EventTableInfo
}

// Invite represents one row from table 'trustyca.invite'.
// Primary key: id
// Indexes:
//
//	idx_invite_email: [email]
//	idx_invite_org_project: [org_id,project_id]
//	invite_pkey: PRIMARY UNIQUE [id]
//	unique_invite_org_project_email: UNIQUE [email,org_id,project_id]
type Invite struct {
	// ID represents 'id' column of 'bigint'
	ID xdb.ID `db:"id,int8,index,primary" json:",omitempty"`
	// OrgID represents 'org_id' column of 'bigint'
	OrgID xdb.ID `db:"org_id,int8,index,fk:trustyca.project.id" json:",omitempty"`
	// ProjectID represents 'project_id' column of 'bigint'
	ProjectID xdb.ID `db:"project_id,int8,null,index,fk:trustyca.project.id" json:",omitempty"`
	// InviterID represents 'inviter_id' column of 'bigint'
	InviterID xdb.ID `db:"inviter_id,int8,fk:trustyca.user.id" json:",omitempty"`
	// Email represents 'email' column of 'character varying'
	Email string `db:"email,varchar,max:160,index" json:",omitempty"`
	// Role represents 'role' column of 'integer'
	Role pb.Role_Enum `db:"role,int4" json:",omitempty"`
	// CreatedAt represents 'created_at' column of 'timestamp with time zone'
	CreatedAt xdb.Time `db:"created_at,timestamptz" json:",omitempty"`
	// ExpiresAt represents 'expires_at' column of 'timestamp with time zone'
	ExpiresAt xdb.Time `db:"expires_at,timestamptz,null" json:",omitempty"`
}

// ScanRow scans one row for invite.
func (m *Invite) ScanRow(rows xdb.Row) error {
	err := rows.Scan(
		&m.ID,
		&m.OrgID,
		&m.ProjectID,
		&m.InviterID,
		&m.Email,
		&m.Role,
		&m.CreatedAt,
		&m.ExpiresAt,
	)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

type InviteSlice []*Invite
type InviteResult struct {
	Rows        InviteSlice
	NextOffset  uint32
	HasNextPage bool
	Cursor      string
}

func (p *InviteResult) SetResult(rows []*Invite, hasNextPage bool, nextOffset uint32) {
	p.Rows = rows
	p.NextOffset = nextOffset
	p.HasNextPage = hasNextPage
}

func (p *InviteResult) SetResultWithCursor(rows []*Invite, hasNextPage bool, cursor func(lastRow *Invite) string) {
	p.Rows = rows
	p.HasNextPage = hasNextPage
	if hasNextPage && len(rows) > 0 {
		p.Cursor = cursor(rows[len(rows)-1])
	}
}

func (p *InviteResult) GetTableInfo() *xdbschema.TableInfo {
	return &schema.InviteTableInfo
}

// Issuer represents one row from table 'trustyca.issuer'.
// Primary key: id
// Indexes:
//
//	idx_issuer_notafter: [not_after]
//	idx_issuer_org_project_status: [org_id,project_id,status]
//	idx_issuer_parent: [parent_id]
//	issuer_pkey: PRIMARY UNIQUE [id]
//	unique_issuer_org_project_label: UNIQUE [org_id,project_id,label]
//	unique_issuer_skid: UNIQUE [skid]
type Issuer struct {
	// ID represents 'id' column of 'bigint'
	ID xdb.ID `db:"id,int8,index,primary" json:",omitempty"`
	// OrgID represents 'org_id' column of 'bigint'
	OrgID xdb.ID `db:"org_id,int8,null,index" json:",omitempty"`
	// ProjectID represents 'project_id' column of 'bigint'
	ProjectID xdb.ID `db:"project_id,int8,null,index" json:",omitempty"`
	// Label represents 'label' column of 'character varying'
	Label string `db:"label,varchar,max:64,index" json:",omitempty"`
	// Type represents 'type' column of 'integer'
	Type pb.AuthorityType_Enum `db:"type,int4" json:",omitempty"`
	// Status represents 'status' column of 'integer'
	Status pb.IssuerStatus_Enum `db:"status,int4,index" json:",omitempty"`
	// ParentID represents 'parent_id' column of 'bigint'
	ParentID xdb.ID `db:"parent_id,int8,null,index" json:",omitempty"`
	// Skid represents 'skid' column of 'character varying'
	Skid string `db:"skid,varchar,max:64,index" json:",omitempty"`
	// Ikid represents 'ikid' column of 'character varying'
	Ikid string `db:"ikid,varchar,max:64" json:",omitempty"`
	// SerialNumber represents 'serial_number' column of 'character varying'
	SerialNumber string `db:"serial_number,varchar,max:64" json:",omitempty"`
	// Subject represents 'subject' column of 'character varying'
	Subject string `db:"subject,varchar,max:260" json:",omitempty"`
	// Issuer represents 'issuer' column of 'character varying'
	Issuer string `db:"issuer,varchar,max:260" json:",omitempty"`
	// Sha256 represents 'sha256' column of 'character varying'
	Sha256 string `db:"sha256,varchar,max:64" json:",omitempty"`
	// NotBefore represents 'not_before' column of 'timestamp with time zone'
	NotBefore xdb.Time `db:"not_before,timestamptz,null" json:",omitempty"`
	// NotAfter represents 'not_after' column of 'timestamp with time zone'
	NotAfter xdb.Time `db:"not_after,timestamptz,null,index" json:",omitempty"`
	// Pem represents 'pem' column of 'text'
	Pem string `db:"pem,text" json:",omitempty"`
	// ChainPem represents 'chain_pem' column of 'text'
	ChainPem string `db:"chain_pem,text" json:",omitempty"`
	// RootPem represents 'root_pem' column of 'text'
	RootPem string `db:"root_pem,text" json:",omitempty"`
	// CsrPem represents 'csr_pem' column of 'text'
	CsrPem string `db:"csr_pem,text" json:",omitempty"`
	// KeyProvider represents 'key_provider' column of 'character varying'
	KeyProvider string `db:"key_provider,varchar,max:64" json:",omitempty"`
	// KeyID represents 'key_id' column of 'character varying'
	KeyID string `db:"key_id,varchar,max:260" json:",omitempty"`
	// KeyProtected represents 'key_protected' column of 'text'
	KeyProtected xdb.NULLString `db:"key_protected,text,null" json:",omitempty"`
	// Config represents 'config' column of 'jsonb'
	Config xdb.NULLString `db:"config,jsonb" json:",omitempty"`
	// CrlNumber represents 'crl_number' column of 'bigint'
	CrlNumber int64 `db:"crl_number,int8" json:",omitempty"`
	// CreatedAt represents 'created_at' column of 'timestamp with time zone'
	CreatedAt xdb.Time `db:"created_at,timestamptz" json:",omitempty"`
	// UpdatedAt represents 'updated_at' column of 'timestamp with time zone'
	UpdatedAt xdb.Time `db:"updated_at,timestamptz" json:",omitempty"`
}

// ScanRow scans one row for issuer.
func (m *Issuer) ScanRow(rows xdb.Row) error {
	err := rows.Scan(
		&m.ID,
		&m.OrgID,
		&m.ProjectID,
		&m.Label,
		&m.Type,
		&m.Status,
		&m.ParentID,
		&m.Skid,
		&m.Ikid,
		&m.SerialNumber,
		&m.Subject,
		&m.Issuer,
		&m.Sha256,
		&m.NotBefore,
		&m.NotAfter,
		&m.Pem,
		&m.ChainPem,
		&m.RootPem,
		&m.CsrPem,
		&m.KeyProvider,
		&m.KeyID,
		&m.KeyProtected,
		&m.Config,
		&m.CrlNumber,
		&m.CreatedAt,
		&m.UpdatedAt,
	)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

type IssuerSlice []*Issuer
type IssuerResult struct {
	Rows        IssuerSlice
	NextOffset  uint32
	HasNextPage bool
	Cursor      string
}

func (p *IssuerResult) SetResult(rows []*Issuer, hasNextPage bool, nextOffset uint32) {
	p.Rows = rows
	p.NextOffset = nextOffset
	p.HasNextPage = hasNextPage
}

func (p *IssuerResult) SetResultWithCursor(rows []*Issuer, hasNextPage bool, cursor func(lastRow *Issuer) string) {
	p.Rows = rows
	p.HasNextPage = hasNextPage
	if hasNextPage && len(rows) > 0 {
		p.Cursor = cursor(rows[len(rows)-1])
	}
}

func (p *IssuerResult) GetTableInfo() *xdbschema.TableInfo {
	return &schema.IssuerTableInfo
}

// Login represents one row from table 'trustyca.login'.
// Primary key: id
// Indexes:
//
//	idx_login_email: [email]
//	idx_login_last_at: [last_at]
//	login_pkey: PRIMARY UNIQUE [id]
//	unique_login_provider_email: UNIQUE [provider,email]
type Login struct {
	// ID represents 'id' column of 'bigint'
	ID xdb.ID `db:"id,int8,index,primary" json:",omitempty"`
	// ExternalID represents 'external_id' column of 'character varying'
	ExternalID string `db:"external_id,varchar,max:64" json:",omitempty"`
	// Provider represents 'provider' column of 'integer'
	Provider pb.IDP_Enum `db:"provider,int4,index" json:",omitempty"`
	// Email represents 'email' column of 'character varying'
	Email string `db:"email,varchar,max:160,index" json:",omitempty"`
	// EmailVerified represents 'email_verified' column of 'boolean'
	EmailVerified bool `db:"email_verified,bool" json:",omitempty"`
	// Name represents 'name' column of 'character varying'
	Name string `db:"name,varchar,max:64" json:",omitempty"`
	// AccessToken represents 'access_token' column of 'text'
	AccessToken string `db:"access_token,text" json:",omitempty"`
	// RefreshToken represents 'refresh_token' column of 'text'
	RefreshToken string `db:"refresh_token,text" json:",omitempty"`
	// TokenExpiresAt represents 'token_expires_at' column of 'timestamp with time zone'
	TokenExpiresAt xdb.Time `db:"token_expires_at,timestamptz,null" json:",omitempty"`
	// Count represents 'count' column of 'integer'
	Count uint32 `db:"count,int4" json:",omitempty"`
	// LastAt represents 'last_at' column of 'timestamp with time zone'
	LastAt xdb.Time `db:"last_at,timestamptz,null,index" json:",omitempty"`
}

// ScanRow scans one row for login.
func (m *Login) ScanRow(rows xdb.Row) error {
	err := rows.Scan(
		&m.ID,
		&m.ExternalID,
		&m.Provider,
		&m.Email,
		&m.EmailVerified,
		&m.Name,
		&m.AccessToken,
		&m.RefreshToken,
		&m.TokenExpiresAt,
		&m.Count,
		&m.LastAt,
	)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

type LoginSlice []*Login
type LoginResult struct {
	Rows        LoginSlice
	NextOffset  uint32
	HasNextPage bool
	Cursor      string
}

func (p *LoginResult) SetResult(rows []*Login, hasNextPage bool, nextOffset uint32) {
	p.Rows = rows
	p.NextOffset = nextOffset
	p.HasNextPage = hasNextPage
}

func (p *LoginResult) SetResultWithCursor(rows []*Login, hasNextPage bool, cursor func(lastRow *Login) string) {
	p.Rows = rows
	p.HasNextPage = hasNextPage
	if hasNextPage && len(rows) > 0 {
		p.Cursor = cursor(rows[len(rows)-1])
	}
}

func (p *LoginResult) GetTableInfo() *xdbschema.TableInfo {
	return &schema.LoginTableInfo
}

// Membership represents one row from table 'trustyca.membership'.
// Primary key: id
// Indexes:
//
//	idx_membership_org_project: [org_id,project_id]
//	idx_membership_user_id: [user_id]
//	membership_pkey: PRIMARY UNIQUE [id]
//	unique_membership_org_project_user: UNIQUE [user_id,org_id,project_id]
type Membership struct {
	// ID represents 'id' column of 'bigint'
	ID xdb.ID `db:"id,int8,index,primary" json:",omitempty"`
	// OrgID represents 'org_id' column of 'bigint'
	OrgID xdb.ID `db:"org_id,int8,index,fk:trustyca.project.id" json:",omitempty"`
	// ProjectID represents 'project_id' column of 'bigint'
	ProjectID xdb.ID `db:"project_id,int8,null,index,fk:trustyca.project.id" json:",omitempty"`
	// UserID represents 'user_id' column of 'bigint'
	UserID xdb.ID `db:"user_id,int8,index,fk:trustyca.user.id" json:",omitempty"`
	// Role represents 'role' column of 'integer'
	Role pb.Role_Enum `db:"role,int4" json:",omitempty"`
	// CreatedAt represents 'created_at' column of 'timestamp with time zone'
	CreatedAt xdb.Time `db:"created_at,timestamptz" json:",omitempty"`
}

// ScanRow scans one row for membership.
func (m *Membership) ScanRow(rows xdb.Row) error {
	err := rows.Scan(
		&m.ID,
		&m.OrgID,
		&m.ProjectID,
		&m.UserID,
		&m.Role,
		&m.CreatedAt,
	)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

type MembershipSlice []*Membership
type MembershipResult struct {
	Rows        MembershipSlice
	NextOffset  uint32
	HasNextPage bool
	Cursor      string
}

func (p *MembershipResult) SetResult(rows []*Membership, hasNextPage bool, nextOffset uint32) {
	p.Rows = rows
	p.NextOffset = nextOffset
	p.HasNextPage = hasNextPage
}

func (p *MembershipResult) SetResultWithCursor(rows []*Membership, hasNextPage bool, cursor func(lastRow *Membership) string) {
	p.Rows = rows
	p.HasNextPage = hasNextPage
	if hasNextPage && len(rows) > 0 {
		p.Cursor = cursor(rows[len(rows)-1])
	}
}

func (p *MembershipResult) GetTableInfo() *xdbschema.TableInfo {
	return &schema.MembershipTableInfo
}

// Org represents one row from table 'trustyca.org'.
// Primary key: id
// Indexes:
//
//	org_pkey: PRIMARY UNIQUE [id]
//	unique_org_alias: UNIQUE [alias]
type Org struct {
	// ID represents 'id' column of 'bigint'
	ID xdb.ID `db:"id,int8,index,primary" json:",omitempty"`
	// Alias represents 'alias' column of 'character varying'
	Alias string `db:"alias,varchar,max:32,index" json:",omitempty"`
	// Name represents 'name' column of 'character varying'
	Name string `db:"name,varchar,max:64" json:",omitempty"`
	// Description represents 'description' column of 'text'
	Description xdb.NULLString `db:"description,text,null" json:",omitempty"`
	// Status represents 'status' column of 'integer'
	Status pb.ItemStatus_Enum `db:"status,int4" json:",omitempty"`
	// CreatedAt represents 'created_at' column of 'timestamp with time zone'
	CreatedAt xdb.Time `db:"created_at,timestamptz" json:",omitempty"`
}

// ScanRow scans one row for org.
func (m *Org) ScanRow(rows xdb.Row) error {
	err := rows.Scan(
		&m.ID,
		&m.Alias,
		&m.Name,
		&m.Description,
		&m.Status,
		&m.CreatedAt,
	)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

type OrgSlice []*Org
type OrgResult struct {
	Rows        OrgSlice
	NextOffset  uint32
	HasNextPage bool
	Cursor      string
}

func (p *OrgResult) SetResult(rows []*Org, hasNextPage bool, nextOffset uint32) {
	p.Rows = rows
	p.NextOffset = nextOffset
	p.HasNextPage = hasNextPage
}

func (p *OrgResult) SetResultWithCursor(rows []*Org, hasNextPage bool, cursor func(lastRow *Org) string) {
	p.Rows = rows
	p.HasNextPage = hasNextPage
	if hasNextPage && len(rows) > 0 {
		p.Cursor = cursor(rows[len(rows)-1])
	}
}

func (p *OrgResult) GetTableInfo() *xdbschema.TableInfo {
	return &schema.OrgTableInfo
}

// Project represents one row from table 'trustyca.project'.
// Primary key: id
// Indexes:
//
//	idx_project_org_status: [org_id,status]
//	project_pkey: PRIMARY UNIQUE [id]
//	unique_project_org_alias: UNIQUE [alias,org_id]
//	unique_project_org_id: UNIQUE [id,org_id]
type Project struct {
	// ID represents 'id' column of 'bigint'
	ID xdb.ID `db:"id,int8,index,primary" json:",omitempty"`
	// OrgID represents 'org_id' column of 'bigint'
	OrgID xdb.ID `db:"org_id,int8,index,fk:trustyca.org.id" json:",omitempty"`
	// Alias represents 'alias' column of 'character varying'
	Alias string `db:"alias,varchar,max:64,index" json:",omitempty"`
	// Name represents 'name' column of 'character varying'
	Name string `db:"name,varchar,max:64" json:",omitempty"`
	// Description represents 'description' column of 'text'
	Description xdb.NULLString `db:"description,text,null" json:",omitempty"`
	// Status represents 'status' column of 'integer'
	Status pb.ItemStatus_Enum `db:"status,int4,index" json:",omitempty"`
	// CreatedAt represents 'created_at' column of 'timestamp with time zone'
	CreatedAt xdb.Time `db:"created_at,timestamptz" json:",omitempty"`
	// UpdatedAt represents 'updated_at' column of 'timestamp with time zone'
	UpdatedAt xdb.Time `db:"updated_at,timestamptz" json:",omitempty"`
}

// ScanRow scans one row for project.
func (m *Project) ScanRow(rows xdb.Row) error {
	err := rows.Scan(
		&m.ID,
		&m.OrgID,
		&m.Alias,
		&m.Name,
		&m.Description,
		&m.Status,
		&m.CreatedAt,
		&m.UpdatedAt,
	)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

type ProjectSlice []*Project
type ProjectResult struct {
	Rows        ProjectSlice
	NextOffset  uint32
	HasNextPage bool
	Cursor      string
}

func (p *ProjectResult) SetResult(rows []*Project, hasNextPage bool, nextOffset uint32) {
	p.Rows = rows
	p.NextOffset = nextOffset
	p.HasNextPage = hasNextPage
}

func (p *ProjectResult) SetResultWithCursor(rows []*Project, hasNextPage bool, cursor func(lastRow *Project) string) {
	p.Rows = rows
	p.HasNextPage = hasNextPage
	if hasNextPage && len(rows) > 0 {
		p.Cursor = cursor(rows[len(rows)-1])
	}
}

func (p *ProjectResult) GetTableInfo() *xdbschema.TableInfo {
	return &schema.ProjectTableInfo
}

// Revoked represents one row from table 'trustyca.revoked'.
// Primary key: id
// Indexes:
//
//	idx_revoked_ikid_notafter: [not_after,ikid]
//	idx_revoked_org_project_id_desc: [project_id,id,org_id]
//	revoked_pkey: PRIMARY UNIQUE [id]
//	unique_revoked_certificate: UNIQUE [certificate_id]
type Revoked struct {
	// ID represents 'id' column of 'bigint'
	ID xdb.ID `db:"id,int8,index,primary" json:",omitempty"`
	// OrgID represents 'org_id' column of 'bigint'
	OrgID xdb.ID `db:"org_id,int8,null,index" json:",omitempty"`
	// ProjectID represents 'project_id' column of 'bigint'
	ProjectID xdb.ID `db:"project_id,int8,null,index" json:",omitempty"`
	// CertificateID represents 'certificate_id' column of 'bigint'
	CertificateID xdb.ID `db:"certificate_id,int8,index,fk:trustyca.certificate.id" json:",omitempty"`
	// Ikid represents 'ikid' column of 'character varying'
	Ikid string `db:"ikid,varchar,max:64,index" json:",omitempty"`
	// SerialNumber represents 'serial_number' column of 'character varying'
	SerialNumber string `db:"serial_number,varchar,max:64" json:",omitempty"`
	// NotAfter represents 'not_after' column of 'timestamp with time zone'
	NotAfter xdb.Time `db:"not_after,timestamptz,index" json:",omitempty"`
	// RevokedAt represents 'revoked_at' column of 'timestamp with time zone'
	RevokedAt xdb.Time `db:"revoked_at,timestamptz" json:",omitempty"`
	// Reason represents 'reason' column of 'integer'
	Reason pb.ReasonCode_Enum `db:"reason,int4" json:",omitempty"`
	// ReasonText represents 'reason_text' column of 'character varying'
	ReasonText string `db:"reason_text,varchar,max:260" json:",omitempty"`
}

// ScanRow scans one row for revoked.
func (m *Revoked) ScanRow(rows xdb.Row) error {
	err := rows.Scan(
		&m.ID,
		&m.OrgID,
		&m.ProjectID,
		&m.CertificateID,
		&m.Ikid,
		&m.SerialNumber,
		&m.NotAfter,
		&m.RevokedAt,
		&m.Reason,
		&m.ReasonText,
	)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

type RevokedSlice []*Revoked
type RevokedResult struct {
	Rows        RevokedSlice
	NextOffset  uint32
	HasNextPage bool
	Cursor      string
}

func (p *RevokedResult) SetResult(rows []*Revoked, hasNextPage bool, nextOffset uint32) {
	p.Rows = rows
	p.NextOffset = nextOffset
	p.HasNextPage = hasNextPage
}

func (p *RevokedResult) SetResultWithCursor(rows []*Revoked, hasNextPage bool, cursor func(lastRow *Revoked) string) {
	p.Rows = rows
	p.HasNextPage = hasNextPage
	if hasNextPage && len(rows) > 0 {
		p.Cursor = cursor(rows[len(rows)-1])
	}
}

func (p *RevokedResult) GetTableInfo() *xdbschema.TableInfo {
	return &schema.RevokedTableInfo
}

// RootCertificate represents one row from table 'trustyca.root_certificate'.
// Primary key: id
// Indexes:
//
//	idx_root_certificate_notafter: [not_after]
//	idx_root_certificate_org: [org_id]
//	idx_root_certificate_skid: [skid]
//	root_certificate_pkey: PRIMARY UNIQUE [id]
//	unique_root_certificate_sha256: UNIQUE [sha256]
type RootCertificate struct {
	// ID represents 'id' column of 'bigint'
	ID xdb.ID `db:"id,int8,index,primary" json:",omitempty"`
	// OrgID represents 'org_id' column of 'bigint'
	OrgID xdb.ID `db:"org_id,int8,null,index" json:",omitempty"`
	// Skid represents 'skid' column of 'character varying'
	Skid string `db:"skid,varchar,max:64,index" json:",omitempty"`
	// NotBefore represents 'not_before' column of 'timestamp with time zone'
	NotBefore xdb.Time `db:"not_before,timestamptz" json:",omitempty"`
	// NotAfter represents 'not_after' column of 'timestamp with time zone'
	NotAfter xdb.Time `db:"not_after,timestamptz,index" json:",omitempty"`
	// Subject represents 'subject' column of 'character varying'
	Subject string `db:"subject,varchar,max:260" json:",omitempty"`
	// Sha256 represents 'sha256' column of 'character varying'
	Sha256 string `db:"sha256,varchar,max:64,index" json:",omitempty"`
	// Trust represents 'trust' column of 'integer'
	Trust pb.Trust_Enum `db:"trust,int4" json:",omitempty"`
	// Pem represents 'pem' column of 'text'
	Pem string `db:"pem,text" json:",omitempty"`
	// CreatedAt represents 'created_at' column of 'timestamp with time zone'
	CreatedAt xdb.Time `db:"created_at,timestamptz" json:",omitempty"`
}

// ScanRow scans one row for root_certificate.
func (m *RootCertificate) ScanRow(rows xdb.Row) error {
	err := rows.Scan(
		&m.ID,
		&m.OrgID,
		&m.Skid,
		&m.NotBefore,
		&m.NotAfter,
		&m.Subject,
		&m.Sha256,
		&m.Trust,
		&m.Pem,
		&m.CreatedAt,
	)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

type RootCertificateSlice []*RootCertificate
type RootCertificateResult struct {
	Rows        RootCertificateSlice
	NextOffset  uint32
	HasNextPage bool
	Cursor      string
}

func (p *RootCertificateResult) SetResult(rows []*RootCertificate, hasNextPage bool, nextOffset uint32) {
	p.Rows = rows
	p.NextOffset = nextOffset
	p.HasNextPage = hasNextPage
}

func (p *RootCertificateResult) SetResultWithCursor(rows []*RootCertificate, hasNextPage bool, cursor func(lastRow *RootCertificate) string) {
	p.Rows = rows
	p.HasNextPage = hasNextPage
	if hasNextPage && len(rows) > 0 {
		p.Cursor = cursor(rows[len(rows)-1])
	}
}

func (p *RootCertificateResult) GetTableInfo() *xdbschema.TableInfo {
	return &schema.RootCertificateTableInfo
}

// SchemaMigration represents one row from table 'trustyca.schema_migrations'.
// Primary key: version
// Indexes:
//
//	schema_migrations_pkey: PRIMARY UNIQUE [version]
type SchemaMigration struct {
	// Version represents 'version' column of 'bigint'
	Version int64 `db:"version,int8,index,primary" json:",omitempty"`
	// Dirty represents 'dirty' column of 'boolean'
	Dirty bool `db:"dirty,bool" json:",omitempty"`
}

// ScanRow scans one row for schema_migrations.
func (m *SchemaMigration) ScanRow(rows xdb.Row) error {
	err := rows.Scan(
		&m.Version,
		&m.Dirty,
	)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

type SchemaMigrationSlice []*SchemaMigration
type SchemaMigrationResult struct {
	Rows        SchemaMigrationSlice
	NextOffset  uint32
	HasNextPage bool
	Cursor      string
}

func (p *SchemaMigrationResult) SetResult(rows []*SchemaMigration, hasNextPage bool, nextOffset uint32) {
	p.Rows = rows
	p.NextOffset = nextOffset
	p.HasNextPage = hasNextPage
}

func (p *SchemaMigrationResult) SetResultWithCursor(rows []*SchemaMigration, hasNextPage bool, cursor func(lastRow *SchemaMigration) string) {
	p.Rows = rows
	p.HasNextPage = hasNextPage
	if hasNextPage && len(rows) > 0 {
		p.Cursor = cursor(rows[len(rows)-1])
	}
}

func (p *SchemaMigrationResult) GetTableInfo() *xdbschema.TableInfo {
	return &schema.SchemaMigrationTableInfo
}

// User represents one row from table 'trustyca.user'.
// Primary key: id
// Indexes:
//
//	unique_user_email: UNIQUE [email]
//	user_pkey: PRIMARY UNIQUE [id]
type User struct {
	// ID represents 'id' column of 'bigint'
	ID xdb.ID `db:"id,int8,index,primary" json:",omitempty"`
	// Email represents 'email' column of 'character varying'
	Email string `db:"email,varchar,max:160,index" json:",omitempty"`
	// EmailVerified represents 'email_verified' column of 'boolean'
	EmailVerified bool `db:"email_verified,bool" json:",omitempty"`
	// Name represents 'name' column of 'character varying'
	Name string `db:"name,varchar,max:64" json:",omitempty"`
}

// ScanRow scans one row for user.
func (m *User) ScanRow(rows xdb.Row) error {
	err := rows.Scan(
		&m.ID,
		&m.Email,
		&m.EmailVerified,
		&m.Name,
	)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

type UserSlice []*User
type UserResult struct {
	Rows        UserSlice
	NextOffset  uint32
	HasNextPage bool
	Cursor      string
}

func (p *UserResult) SetResult(rows []*User, hasNextPage bool, nextOffset uint32) {
	p.Rows = rows
	p.NextOffset = nextOffset
	p.HasNextPage = hasNextPage
}

func (p *UserResult) SetResultWithCursor(rows []*User, hasNextPage bool, cursor func(lastRow *User) string) {
	p.Rows = rows
	p.HasNextPage = hasNextPage
	if hasNextPage && len(rows) > 0 {
		p.Cursor = cursor(rows[len(rows)-1])
	}
}

func (p *UserResult) GetTableInfo() *xdbschema.TableInfo {
	return &schema.UserTableInfo
}

// MembershipInfo represents one row from table 'trustyca.vw_membership_info'.
type MembershipInfo struct {
	// ID represents 'id' column of 'bigint'
	ID xdb.ID `db:"id,int8,null" json:",omitempty"`
	// OrgID represents 'org_id' column of 'bigint'
	OrgID xdb.ID `db:"org_id,int8,null" json:",omitempty"`
	// ProjectID represents 'project_id' column of 'bigint'
	ProjectID xdb.ID `db:"project_id,int8,null" json:",omitempty"`
	// OrgAlias represents 'org_alias' column of 'character varying'
	OrgAlias string `db:"org_alias,varchar,max:32,null" json:",omitempty"`
	// OrgName represents 'org_name' column of 'character varying'
	OrgName string `db:"org_name,varchar,max:64,null" json:",omitempty"`
	// OrgStatus represents 'org_status' column of 'integer'
	OrgStatus xdb.Int32 `db:"org_status,int4,null" json:",omitempty"`
	// ProjectAlias represents 'project_alias' column of 'character varying'
	ProjectAlias string `db:"project_alias,varchar,null" json:",omitempty"`
	// ProjectName represents 'project_name' column of 'character varying'
	ProjectName string `db:"project_name,varchar,null" json:",omitempty"`
	// UserID represents 'user_id' column of 'bigint'
	UserID xdb.ID `db:"user_id,int8,null" json:",omitempty"`
	// Email represents 'email' column of 'character varying'
	Email string `db:"email,varchar,max:160,null" json:",omitempty"`
	// Name represents 'name' column of 'character varying'
	Name string `db:"name,varchar,max:64,null" json:",omitempty"`
	// Role represents 'role' column of 'integer'
	Role pb.Role_Enum `db:"role,int4,null" json:",omitempty"`
	// CreatedAt represents 'created_at' column of 'timestamp with time zone'
	CreatedAt xdb.Time `db:"created_at,timestamptz,null" json:",omitempty"`
}

// ScanRow scans one row for vw_membership_info.
func (m *MembershipInfo) ScanRow(rows xdb.Row) error {
	err := rows.Scan(
		&m.ID,
		&m.OrgID,
		&m.ProjectID,
		&m.OrgAlias,
		&m.OrgName,
		&m.OrgStatus,
		&m.ProjectAlias,
		&m.ProjectName,
		&m.UserID,
		&m.Email,
		&m.Name,
		&m.Role,
		&m.CreatedAt,
	)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

type MembershipInfoSlice []*MembershipInfo
type MembershipInfoResult struct {
	Rows        MembershipInfoSlice
	NextOffset  uint32
	HasNextPage bool
	Cursor      string
}

func (p *MembershipInfoResult) SetResult(rows []*MembershipInfo, hasNextPage bool, nextOffset uint32) {
	p.Rows = rows
	p.NextOffset = nextOffset
	p.HasNextPage = hasNextPage
}

func (p *MembershipInfoResult) SetResultWithCursor(rows []*MembershipInfo, hasNextPage bool, cursor func(lastRow *MembershipInfo) string) {
	p.Rows = rows
	p.HasNextPage = hasNextPage
	if hasNextPage && len(rows) > 0 {
		p.Cursor = cursor(rows[len(rows)-1])
	}
}

func (p *MembershipInfoResult) GetTableInfo() *xdbschema.TableInfo {
	return &schema.MembershipInfoTableInfo
}
