// DO NOT EDIT!
// This file is MACHINE GENERATED
// DB: trustycadb

package schema

import (
	xdbschema "github.com/effective-security/xdb/schema"
	"github.com/effective-security/xdb/xsql"
)

// Dialect provides Dialect for trustycadb
var Dialect = xsql.Postgres

// EventTableInfo provides table info for 'event'
var EventTableInfo = xdbschema.TableInfo{
	SchemaName: "trustyca.event",
	Schema:     "trustyca",
	Name:       "event",
	PrimaryKey: "id",
	Columns:    []string{"id", "org_id", "type", "title", "description", "metadata", "ref_id", "email", "source", "created_at"},
	Indexes:    []string{"event_pkey", "idx_event_email", "idx_event_org_created_id_desc", "idx_event_org_id", "idx_event_org_ref_id", "idx_event_type"},
	Dialect:    xsql.Postgres,
}

// InviteTableInfo provides table info for 'invite'
var InviteTableInfo = xdbschema.TableInfo{
	SchemaName: "trustyca.invite",
	Schema:     "trustyca",
	Name:       "invite",
	PrimaryKey: "id",
	Columns:    []string{"id", "org_id", "inviter_id", "email", "role", "created_at"},
	Indexes:    []string{"idx_invite_email", "idx_invite_org_id", "invites_pkey", "unique_invite_org_id_email"},
	Dialect:    xsql.Postgres,
}

// LlmModelTableInfo provides table info for 'llm_model'
var LlmModelTableInfo = xdbschema.TableInfo{
	SchemaName: "trustyca.llm_model",
	Schema:     "trustyca",
	Name:       "llm_model",
	PrimaryKey: "id",
	Columns:    []string{"id", "provider", "name", "description", "status", "metadata", "cost_input_token", "cost_output_token", "cost_cached_input_read", "cost_cached_input_write", "cost_reasoning_token", "created_at", "updated_at"},
	Indexes:    []string{"idx_llm_model_name", "llm_model_pkey", "unique_llm_model_provider_name"},
	Dialect:    xsql.Postgres,
}

// LoginTableInfo provides table info for 'login'
var LoginTableInfo = xdbschema.TableInfo{
	SchemaName: "trustyca.login",
	Schema:     "trustyca",
	Name:       "login",
	PrimaryKey: "id",
	Columns:    []string{"id", "external_id", "provider", "email", "email_verified", "name", "access_token", "refresh_token", "token_expires_at", "count", "last_at"},
	Indexes:    []string{"idx_login_email", "idx_login_last_at", "login_pkey", "unique_login_provider_email"},
	Dialect:    xsql.Postgres,
}

// MembershipTableInfo provides table info for 'membership'
var MembershipTableInfo = xdbschema.TableInfo{
	SchemaName: "trustyca.membership",
	Schema:     "trustyca",
	Name:       "membership",
	PrimaryKey: "id",
	Columns:    []string{"id", "org_id", "user_id", "role", "created_at"},
	Indexes:    []string{"idx_membership_org_id", "idx_membership_user_id", "membership_org_user", "membership_pkey"},
	Dialect:    xsql.Postgres,
}

// OrgTableInfo provides table info for 'org'
var OrgTableInfo = xdbschema.TableInfo{
	SchemaName: "trustyca.org",
	Schema:     "trustyca",
	Name:       "org",
	PrimaryKey: "id",
	Columns:    []string{"id", "alias", "name", "description", "status", "created_at"},
	Indexes:    []string{"org_pkey", "unique_org_alias"},
	Dialect:    xsql.Postgres,
}

// SchemaMigrationTableInfo provides table info for 'schema_migrations'
var SchemaMigrationTableInfo = xdbschema.TableInfo{
	SchemaName: "trustyca.schema_migrations",
	Schema:     "trustyca",
	Name:       "schema_migrations",
	PrimaryKey: "version",
	Columns:    []string{"version", "dirty"},
	Indexes:    []string{"schema_migrations_pkey"},
	Dialect:    xsql.Postgres,
}

// UserTableInfo provides table info for 'user'
var UserTableInfo = xdbschema.TableInfo{
	SchemaName: "trustyca.user",
	Schema:     "trustyca",
	Name:       "user",
	PrimaryKey: "id",
	Columns:    []string{"id", "email", "email_verified", "name"},
	Indexes:    []string{"unique_user_email", "user_pkey"},
	Dialect:    xsql.Postgres,
}

// MembershipInfoTableInfo provides table info for 'vw_membership_info'
var MembershipInfoTableInfo = xdbschema.TableInfo{
	SchemaName: "trustyca.vw_membership_info",
	Schema:     "trustyca",
	Name:       "vw_membership_info",
	PrimaryKey: "",
	Columns:    []string{"id", "org_id", "org_alias", "org_name", "org_status", "user_id", "email", "name", "role", "created_at"},
	Indexes:    []string{},
	Dialect:    xsql.Postgres,
}

// TrustycadbTables provides tables map for trustycadb
var TrustycadbTables = map[string]*xdbschema.TableInfo{
	"event":              &EventTableInfo,
	"invite":             &InviteTableInfo,
	"llm_model":          &LlmModelTableInfo,
	"login":              &LoginTableInfo,
	"membership":         &MembershipTableInfo,
	"org":                &OrgTableInfo,
	"schema_migrations":  &SchemaMigrationTableInfo,
	"user":               &UserTableInfo,
	"vw_membership_info": &MembershipInfoTableInfo,
}

// Event provides column definitions for table 'trustyca.event'.
// Primary key: id
// Indexes:
//
//	event_pkey: PRIMARY UNIQUE [id]
//	idx_event_email: [email]
//	idx_event_org_created_id_desc: [org_id,created_at,id]
//	idx_event_org_id: [org_id]
//	idx_event_org_ref_id: [org_id,ref_id]
//	idx_event_type: [type]
var Event = struct {
	Table       *xdbschema.TableInfo
	ID          xdbschema.Column // id bigint
	OrgID       xdbschema.Column // org_id bigint
	Type        xdbschema.Column // type integer
	Title       xdbschema.Column // title character varying
	Description xdbschema.Column // description text
	Metadata    xdbschema.Column // metadata jsonb
	ReferenceID xdbschema.Column // ref_id bigint
	Email       xdbschema.Column // email character varying
	Source      xdbschema.Column // source character varying
	CreatedAt   xdbschema.Column // created_at timestamp with time zone
}{
	Table:       &EventTableInfo,
	ID:          xdbschema.Column{Name: "id", Position: 1, Type: "bigint", UdtType: "int8", Nullable: false},
	OrgID:       xdbschema.Column{Name: "org_id", Position: 2, Type: "bigint", UdtType: "int8", Nullable: false},
	Type:        xdbschema.Column{Name: "type", Position: 3, Type: "integer", UdtType: "int4", Nullable: false},
	Title:       xdbschema.Column{Name: "title", Position: 4, Type: "character varying", UdtType: "varchar", Nullable: false, MaxLength: 256},
	Description: xdbschema.Column{Name: "description", Position: 5, Type: "text", UdtType: "text", Nullable: true},
	Metadata:    xdbschema.Column{Name: "metadata", Position: 6, Type: "jsonb", UdtType: "jsonb", Nullable: false},
	ReferenceID: xdbschema.Column{Name: "ref_id", Position: 7, Type: "bigint", UdtType: "int8", Nullable: true},
	Email:       xdbschema.Column{Name: "email", Position: 8, Type: "character varying", UdtType: "varchar", Nullable: true, MaxLength: 160},
	Source:      xdbschema.Column{Name: "source", Position: 9, Type: "character varying", UdtType: "varchar", Nullable: true, MaxLength: 256},
	CreatedAt:   xdbschema.Column{Name: "created_at", Position: 10, Type: "timestamp with time zone", UdtType: "timestamptz", Nullable: false},
}

// Invite provides column definitions for table 'trustyca.invite'.
// Primary key: id
// Indexes:
//
//	idx_invite_email: [email]
//	idx_invite_org_id: [org_id]
//	invites_pkey: PRIMARY UNIQUE [id]
//	unique_invite_org_id_email: UNIQUE [org_id,email]
var Invite = struct {
	Table     *xdbschema.TableInfo
	ID        xdbschema.Column // id bigint
	OrgID     xdbschema.Column // org_id bigint
	InviterID xdbschema.Column // inviter_id bigint
	Email     xdbschema.Column // email character varying
	Role      xdbschema.Column // role integer
	CreatedAt xdbschema.Column // created_at timestamp with time zone
}{
	Table:     &InviteTableInfo,
	ID:        xdbschema.Column{Name: "id", Position: 1, Type: "bigint", UdtType: "int8", Nullable: false},
	OrgID:     xdbschema.Column{Name: "org_id", Position: 2, Type: "bigint", UdtType: "int8", Nullable: false},
	InviterID: xdbschema.Column{Name: "inviter_id", Position: 3, Type: "bigint", UdtType: "int8", Nullable: false},
	Email:     xdbschema.Column{Name: "email", Position: 4, Type: "character varying", UdtType: "varchar", Nullable: false, MaxLength: 160},
	Role:      xdbschema.Column{Name: "role", Position: 5, Type: "integer", UdtType: "int4", Nullable: false},
	CreatedAt: xdbschema.Column{Name: "created_at", Position: 6, Type: "timestamp with time zone", UdtType: "timestamptz", Nullable: false},
}

// LlmModel provides column definitions for table 'trustyca.llm_model'.
// Primary key: id
// Indexes:
//
//	idx_llm_model_name: [name]
//	llm_model_pkey: PRIMARY UNIQUE [id]
//	unique_llm_model_provider_name: UNIQUE [provider,name]
var LlmModel = struct {
	Table                *xdbschema.TableInfo
	ID                   xdbschema.Column // id bigint
	Provider             xdbschema.Column // provider integer
	Name                 xdbschema.Column // name character varying
	Description          xdbschema.Column // description text
	Status               xdbschema.Column // status integer
	Metadata             xdbschema.Column // metadata jsonb
	CostInputToken       xdbschema.Column // cost_input_token bigint
	CostOutputToken      xdbschema.Column // cost_output_token bigint
	CostCachedInputRead  xdbschema.Column // cost_cached_input_read bigint
	CostCachedInputWrite xdbschema.Column // cost_cached_input_write bigint
	CostReasoningToken   xdbschema.Column // cost_reasoning_token bigint
	CreatedAt            xdbschema.Column // created_at timestamp with time zone
	UpdatedAt            xdbschema.Column // updated_at timestamp with time zone
}{
	Table:                &LlmModelTableInfo,
	ID:                   xdbschema.Column{Name: "id", Position: 1, Type: "bigint", UdtType: "int8", Nullable: false},
	Provider:             xdbschema.Column{Name: "provider", Position: 2, Type: "integer", UdtType: "int4", Nullable: false},
	Name:                 xdbschema.Column{Name: "name", Position: 3, Type: "character varying", UdtType: "varchar", Nullable: false, MaxLength: 64},
	Description:          xdbschema.Column{Name: "description", Position: 4, Type: "text", UdtType: "text", Nullable: true},
	Status:               xdbschema.Column{Name: "status", Position: 5, Type: "integer", UdtType: "int4", Nullable: false},
	Metadata:             xdbschema.Column{Name: "metadata", Position: 6, Type: "jsonb", UdtType: "jsonb", Nullable: false},
	CostInputToken:       xdbschema.Column{Name: "cost_input_token", Position: 7, Type: "bigint", UdtType: "int8", Nullable: false},
	CostOutputToken:      xdbschema.Column{Name: "cost_output_token", Position: 8, Type: "bigint", UdtType: "int8", Nullable: false},
	CostCachedInputRead:  xdbschema.Column{Name: "cost_cached_input_read", Position: 9, Type: "bigint", UdtType: "int8", Nullable: false},
	CostCachedInputWrite: xdbschema.Column{Name: "cost_cached_input_write", Position: 10, Type: "bigint", UdtType: "int8", Nullable: false},
	CostReasoningToken:   xdbschema.Column{Name: "cost_reasoning_token", Position: 11, Type: "bigint", UdtType: "int8", Nullable: false},
	CreatedAt:            xdbschema.Column{Name: "created_at", Position: 12, Type: "timestamp with time zone", UdtType: "timestamptz", Nullable: false},
	UpdatedAt:            xdbschema.Column{Name: "updated_at", Position: 13, Type: "timestamp with time zone", UdtType: "timestamptz", Nullable: false},
}

// Login provides column definitions for table 'trustyca.login'.
// Primary key: id
// Indexes:
//
//	idx_login_email: [email]
//	idx_login_last_at: [last_at]
//	login_pkey: PRIMARY UNIQUE [id]
//	unique_login_provider_email: UNIQUE [provider,email]
var Login = struct {
	Table          *xdbschema.TableInfo
	ID             xdbschema.Column // id bigint
	ExternalID     xdbschema.Column // external_id character varying
	Provider       xdbschema.Column // provider integer
	Email          xdbschema.Column // email character varying
	EmailVerified  xdbschema.Column // email_verified boolean
	Name           xdbschema.Column // name character varying
	AccessToken    xdbschema.Column // access_token text
	RefreshToken   xdbschema.Column // refresh_token text
	TokenExpiresAt xdbschema.Column // token_expires_at timestamp with time zone
	Count          xdbschema.Column // count integer
	LastAt         xdbschema.Column // last_at timestamp with time zone
}{
	Table:          &LoginTableInfo,
	ID:             xdbschema.Column{Name: "id", Position: 1, Type: "bigint", UdtType: "int8", Nullable: false},
	ExternalID:     xdbschema.Column{Name: "external_id", Position: 2, Type: "character varying", UdtType: "varchar", Nullable: false, MaxLength: 64},
	Provider:       xdbschema.Column{Name: "provider", Position: 3, Type: "integer", UdtType: "int4", Nullable: false},
	Email:          xdbschema.Column{Name: "email", Position: 4, Type: "character varying", UdtType: "varchar", Nullable: false, MaxLength: 160},
	EmailVerified:  xdbschema.Column{Name: "email_verified", Position: 5, Type: "boolean", UdtType: "bool", Nullable: false},
	Name:           xdbschema.Column{Name: "name", Position: 6, Type: "character varying", UdtType: "varchar", Nullable: false, MaxLength: 64},
	AccessToken:    xdbschema.Column{Name: "access_token", Position: 7, Type: "text", UdtType: "text", Nullable: false},
	RefreshToken:   xdbschema.Column{Name: "refresh_token", Position: 8, Type: "text", UdtType: "text", Nullable: false},
	TokenExpiresAt: xdbschema.Column{Name: "token_expires_at", Position: 9, Type: "timestamp with time zone", UdtType: "timestamptz", Nullable: true},
	Count:          xdbschema.Column{Name: "count", Position: 10, Type: "integer", UdtType: "int4", Nullable: false},
	LastAt:         xdbschema.Column{Name: "last_at", Position: 11, Type: "timestamp with time zone", UdtType: "timestamptz", Nullable: true},
}

// Membership provides column definitions for table 'trustyca.membership'.
// Primary key: id
// Indexes:
//
//	idx_membership_org_id: [org_id]
//	idx_membership_user_id: [user_id]
//	membership_org_user: UNIQUE [org_id,user_id]
//	membership_pkey: PRIMARY UNIQUE [id]
var Membership = struct {
	Table     *xdbschema.TableInfo
	ID        xdbschema.Column // id bigint
	OrgID     xdbschema.Column // org_id bigint
	UserID    xdbschema.Column // user_id bigint
	Role      xdbschema.Column // role integer
	CreatedAt xdbschema.Column // created_at timestamp with time zone
}{
	Table:     &MembershipTableInfo,
	ID:        xdbschema.Column{Name: "id", Position: 1, Type: "bigint", UdtType: "int8", Nullable: false},
	OrgID:     xdbschema.Column{Name: "org_id", Position: 2, Type: "bigint", UdtType: "int8", Nullable: false},
	UserID:    xdbschema.Column{Name: "user_id", Position: 3, Type: "bigint", UdtType: "int8", Nullable: false},
	Role:      xdbschema.Column{Name: "role", Position: 4, Type: "integer", UdtType: "int4", Nullable: false},
	CreatedAt: xdbschema.Column{Name: "created_at", Position: 5, Type: "timestamp with time zone", UdtType: "timestamptz", Nullable: false},
}

// Org provides column definitions for table 'trustyca.org'.
// Primary key: id
// Indexes:
//
//	org_pkey: PRIMARY UNIQUE [id]
//	unique_org_alias: UNIQUE [alias]
var Org = struct {
	Table       *xdbschema.TableInfo
	ID          xdbschema.Column // id bigint
	Alias       xdbschema.Column // alias character varying
	Name        xdbschema.Column // name character varying
	Description xdbschema.Column // description text
	Status      xdbschema.Column // status integer
	CreatedAt   xdbschema.Column // created_at timestamp with time zone
}{
	Table:       &OrgTableInfo,
	ID:          xdbschema.Column{Name: "id", Position: 1, Type: "bigint", UdtType: "int8", Nullable: false},
	Alias:       xdbschema.Column{Name: "alias", Position: 2, Type: "character varying", UdtType: "varchar", Nullable: false, MaxLength: 32},
	Name:        xdbschema.Column{Name: "name", Position: 3, Type: "character varying", UdtType: "varchar", Nullable: false, MaxLength: 64},
	Description: xdbschema.Column{Name: "description", Position: 4, Type: "text", UdtType: "text", Nullable: true},
	Status:      xdbschema.Column{Name: "status", Position: 5, Type: "integer", UdtType: "int4", Nullable: false},
	CreatedAt:   xdbschema.Column{Name: "created_at", Position: 6, Type: "timestamp with time zone", UdtType: "timestamptz", Nullable: false},
}

// SchemaMigration provides column definitions for table 'trustyca.schema_migrations'.
// Primary key: version
// Indexes:
//
//	schema_migrations_pkey: PRIMARY UNIQUE [version]
var SchemaMigration = struct {
	Table   *xdbschema.TableInfo
	Version xdbschema.Column // version bigint
	Dirty   xdbschema.Column // dirty boolean
}{
	Table:   &SchemaMigrationTableInfo,
	Version: xdbschema.Column{Name: "version", Position: 1, Type: "bigint", UdtType: "int8", Nullable: false},
	Dirty:   xdbschema.Column{Name: "dirty", Position: 2, Type: "boolean", UdtType: "bool", Nullable: false},
}

// User provides column definitions for table 'trustyca.user'.
// Primary key: id
// Indexes:
//
//	unique_user_email: UNIQUE [email]
//	user_pkey: PRIMARY UNIQUE [id]
var User = struct {
	Table         *xdbschema.TableInfo
	ID            xdbschema.Column // id bigint
	Email         xdbschema.Column // email character varying
	EmailVerified xdbschema.Column // email_verified boolean
	Name          xdbschema.Column // name character varying
}{
	Table:         &UserTableInfo,
	ID:            xdbschema.Column{Name: "id", Position: 1, Type: "bigint", UdtType: "int8", Nullable: false},
	Email:         xdbschema.Column{Name: "email", Position: 2, Type: "character varying", UdtType: "varchar", Nullable: false, MaxLength: 160},
	EmailVerified: xdbschema.Column{Name: "email_verified", Position: 3, Type: "boolean", UdtType: "bool", Nullable: false},
	Name:          xdbschema.Column{Name: "name", Position: 4, Type: "character varying", UdtType: "varchar", Nullable: false, MaxLength: 64},
}

// MembershipInfo provides column definitions for table 'trustyca.vw_membership_info'.
var MembershipInfo = struct {
	Table     *xdbschema.TableInfo
	ID        xdbschema.Column // id bigint
	OrgID     xdbschema.Column // org_id bigint
	OrgAlias  xdbschema.Column // org_alias character varying
	OrgName   xdbschema.Column // org_name character varying
	OrgStatus xdbschema.Column // org_status integer
	UserID    xdbschema.Column // user_id bigint
	Email     xdbschema.Column // email character varying
	Name      xdbschema.Column // name character varying
	Role      xdbschema.Column // role integer
	CreatedAt xdbschema.Column // created_at timestamp with time zone
}{
	Table:     &MembershipInfoTableInfo,
	ID:        xdbschema.Column{Name: "id", Position: 1, Type: "bigint", UdtType: "int8", Nullable: true},
	OrgID:     xdbschema.Column{Name: "org_id", Position: 2, Type: "bigint", UdtType: "int8", Nullable: true},
	OrgAlias:  xdbschema.Column{Name: "org_alias", Position: 3, Type: "character varying", UdtType: "varchar", Nullable: true, MaxLength: 32},
	OrgName:   xdbschema.Column{Name: "org_name", Position: 4, Type: "character varying", UdtType: "varchar", Nullable: true, MaxLength: 64},
	OrgStatus: xdbschema.Column{Name: "org_status", Position: 5, Type: "integer", UdtType: "int4", Nullable: true},
	UserID:    xdbschema.Column{Name: "user_id", Position: 6, Type: "bigint", UdtType: "int8", Nullable: true},
	Email:     xdbschema.Column{Name: "email", Position: 7, Type: "character varying", UdtType: "varchar", Nullable: true, MaxLength: 160},
	Name:      xdbschema.Column{Name: "name", Position: 8, Type: "character varying", UdtType: "varchar", Nullable: true, MaxLength: 64},
	Role:      xdbschema.Column{Name: "role", Position: 9, Type: "integer", UdtType: "int4", Nullable: true},
	CreatedAt: xdbschema.Column{Name: "created_at", Position: 10, Type: "timestamp with time zone", UdtType: "timestamptz", Nullable: true},
}
