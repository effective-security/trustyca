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
)

// Dialect provides Dialect for trustycadb
var Dialect = xsql.Postgres

// Event represents one row from table 'trustyca.event'.
// Primary key: id
// Indexes:
//
//	event_pkey: PRIMARY UNIQUE [id]
//	idx_event_email: [email]
//	idx_event_org_created_id_desc: [org_id,created_at,id]
//	idx_event_org_id: [org_id]
//	idx_event_org_ref_id: [org_id,ref_id]
//	idx_event_type: [type]
type Event struct {
	// ID represents 'id' column of 'bigint'
	ID xdb.ID `db:"id,int8,index,primary" json:",omitempty"`
	// OrgID represents 'org_id' column of 'bigint'
	OrgID xdb.ID `db:"org_id,int8,index,fk:trustyca.org.id" json:",omitempty"`
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
//	idx_invite_org_id: [org_id]
//	invites_pkey: PRIMARY UNIQUE [id]
//	unique_invite_org_id_email: UNIQUE [org_id,email]
type Invite struct {
	// ID represents 'id' column of 'bigint'
	ID xdb.ID `db:"id,int8,index,primary" json:",omitempty"`
	// OrgID represents 'org_id' column of 'bigint'
	OrgID xdb.ID `db:"org_id,int8,index,fk:trustyca.org.id" json:",omitempty"`
	// InviterID represents 'inviter_id' column of 'bigint'
	InviterID xdb.ID `db:"inviter_id,int8,fk:trustyca.user.id" json:",omitempty"`
	// Email represents 'email' column of 'character varying'
	Email string `db:"email,varchar,max:160,index" json:",omitempty"`
	// Role represents 'role' column of 'integer'
	Role pb.Role_Enum `db:"role,int4" json:",omitempty"`
	// CreatedAt represents 'created_at' column of 'timestamp with time zone'
	CreatedAt xdb.Time `db:"created_at,timestamptz" json:",omitempty"`
}

// ScanRow scans one row for invite.
func (m *Invite) ScanRow(rows xdb.Row) error {
	err := rows.Scan(
		&m.ID,
		&m.OrgID,
		&m.InviterID,
		&m.Email,
		&m.Role,
		&m.CreatedAt,
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

// LlmModel represents one row from table 'trustyca.llm_model'.
// Primary key: id
// Indexes:
//
//	idx_llm_model_name: [name]
//	llm_model_pkey: PRIMARY UNIQUE [id]
//	unique_llm_model_provider_name: UNIQUE [provider,name]
type LlmModel struct {
	// ID represents 'id' column of 'bigint'
	ID xdb.ID `db:"id,int8,index,primary" json:",omitempty"`
	// Provider represents 'provider' column of 'integer'
	Provider int32 `db:"provider,int4,index" json:",omitempty"`
	// Name represents 'name' column of 'character varying'
	Name string `db:"name,varchar,max:64,index" json:",omitempty"`
	// Description represents 'description' column of 'text'
	Description xdb.NULLString `db:"description,text,null" json:",omitempty"`
	// Status represents 'status' column of 'integer'
	Status int32 `db:"status,int4" json:",omitempty"`
	// Metadata represents 'metadata' column of 'jsonb'
	Metadata xdb.Metadata `db:"metadata,jsonb" json:",omitempty"`
	// CostInputToken represents 'cost_input_token' column of 'bigint'
	CostInputToken int64 `db:"cost_input_token,int8" json:",omitempty"`
	// CostOutputToken represents 'cost_output_token' column of 'bigint'
	CostOutputToken int64 `db:"cost_output_token,int8" json:",omitempty"`
	// CostCachedInputRead represents 'cost_cached_input_read' column of 'bigint'
	CostCachedInputRead int64 `db:"cost_cached_input_read,int8" json:",omitempty"`
	// CostCachedInputWrite represents 'cost_cached_input_write' column of 'bigint'
	CostCachedInputWrite int64 `db:"cost_cached_input_write,int8" json:",omitempty"`
	// CostReasoningToken represents 'cost_reasoning_token' column of 'bigint'
	CostReasoningToken int64 `db:"cost_reasoning_token,int8" json:",omitempty"`
	// CreatedAt represents 'created_at' column of 'timestamp with time zone'
	CreatedAt xdb.Time `db:"created_at,timestamptz" json:",omitempty"`
	// UpdatedAt represents 'updated_at' column of 'timestamp with time zone'
	UpdatedAt xdb.Time `db:"updated_at,timestamptz" json:",omitempty"`
}

// ScanRow scans one row for llm_model.
func (m *LlmModel) ScanRow(rows xdb.Row) error {
	err := rows.Scan(
		&m.ID,
		&m.Provider,
		&m.Name,
		&m.Description,
		&m.Status,
		&m.Metadata,
		&m.CostInputToken,
		&m.CostOutputToken,
		&m.CostCachedInputRead,
		&m.CostCachedInputWrite,
		&m.CostReasoningToken,
		&m.CreatedAt,
		&m.UpdatedAt,
	)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

type LlmModelSlice []*LlmModel
type LlmModelResult struct {
	Rows        LlmModelSlice
	NextOffset  uint32
	HasNextPage bool
	Cursor      string
}

func (p *LlmModelResult) SetResult(rows []*LlmModel, hasNextPage bool, nextOffset uint32) {
	p.Rows = rows
	p.NextOffset = nextOffset
	p.HasNextPage = hasNextPage
}

func (p *LlmModelResult) SetResultWithCursor(rows []*LlmModel, hasNextPage bool, cursor func(lastRow *LlmModel) string) {
	p.Rows = rows
	p.HasNextPage = hasNextPage
	if hasNextPage && len(rows) > 0 {
		p.Cursor = cursor(rows[len(rows)-1])
	}
}

func (p *LlmModelResult) GetTableInfo() *xdbschema.TableInfo {
	return &schema.LlmModelTableInfo
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
//	idx_membership_org_id: [org_id]
//	idx_membership_user_id: [user_id]
//	membership_org_user: UNIQUE [org_id,user_id]
//	membership_pkey: PRIMARY UNIQUE [id]
type Membership struct {
	// ID represents 'id' column of 'bigint'
	ID xdb.ID `db:"id,int8,index,primary" json:",omitempty"`
	// OrgID represents 'org_id' column of 'bigint'
	OrgID xdb.ID `db:"org_id,int8,index,fk:trustyca.org.id" json:",omitempty"`
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
	// OrgAlias represents 'org_alias' column of 'character varying'
	OrgAlias string `db:"org_alias,varchar,max:32,null" json:",omitempty"`
	// OrgName represents 'org_name' column of 'character varying'
	OrgName string `db:"org_name,varchar,max:64,null" json:",omitempty"`
	// OrgStatus represents 'org_status' column of 'integer'
	OrgStatus xdb.Int32 `db:"org_status,int4,null" json:",omitempty"`
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
		&m.OrgAlias,
		&m.OrgName,
		&m.OrgStatus,
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
