package db

import (
	"context"

	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xdb/pkg/flake"

	// register Postgres driver
	_ "github.com/lib/pq"
	// register file driver for migration
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

//go:generate mockgen -source=trustycadb.go -destination=../../mocks/mocktrustycadb/trustycadb_mock.gen.go -package mocktrustycadb

// OrgsReadonlyDb defines an interface for Read operations on Orgs
type OrgsReadonlyDb interface {
	xdb.IDGenerator

	// GetUser returns User
	GetUser(ctx context.Context, id uint64) (*model.User, error)
	// GetUserByEmail returns User
	GetUserByEmail(ctx context.Context, email string) (*model.User, error)
	// GetLogin returns a login by ID
	GetLogin(ctx context.Context, id uint64) (*model.Login, error)
	// GetLoginsByEmail returns Logins
	GetLoginsByEmail(ctx context.Context, email string) (model.LoginSlice, error)
	// ListLogins returns Logins
	ListLogins(ctx context.Context, limit, offset uint32) (model.LoginSlice, uint32, error)

	// GetOrg returns Org
	GetOrg(ctx context.Context, id uint64) (*model.Org, error)
	// FindOrg returns Org by alias
	FindOrg(ctx context.Context, alias string) (*model.Org, error)
	// ListOrgs lists orgs
	ListOrgs(ctx context.Context, req *query.ListOrgsRequest) (*model.OrgResult, error)
	// GetUserOrgs gets the orgs for a user
	GetUserOrgs(ctx context.Context, userID uint64) (model.OrgSlice, error)

	// GetProject returns Project by ID
	GetProject(ctx context.Context, id uint64) (*model.Project, error)
	// FindProject returns Project by org and alias
	FindProject(ctx context.Context, orgID uint64, alias string) (*model.Project, error)
	// ListProjects lists projects of an org
	ListProjects(ctx context.Context, req *query.ListProjectsRequest) (*model.ProjectResult, error)

	// GetUserMemberships returns all grants of a user in active orgs
	GetUserMemberships(ctx context.Context, userID uint64) (model.MembershipInfoSlice, error)
	// ListMemberships lists memberships of the requested scope
	ListMemberships(ctx context.Context, req *query.ListMembershipsRequest) (model.MembershipInfoSlice, error)

	// GetInvite returns an invite by ID
	GetInvite(ctx context.Context, id uint64) (*model.Invite, error)
	// GetInviteByOrgAndEmail returns an invite by org, scope and email;
	// projectID 0 returns the org-wide invite
	GetInviteByOrgAndEmail(ctx context.Context, orgID, projectID uint64, email string) (*model.Invite, error)
	// GetOrgInvites returns invites of all scopes for an org
	GetOrgInvites(ctx context.Context, orgID uint64) (model.InviteSlice, error)
	// GetUserInvites returns invites for a user's email
	GetUserInvites(ctx context.Context, email string) (model.InviteSlice, error)

	// ListEvents returns events
	ListEvents(ctx context.Context, r *query.ListEventsRequest) (*model.EventResult, error)
	// GetEvent returns Event
	GetEvent(ctx context.Context, id uint64) (*model.Event, error)

	// ListAPIKeys lists API keys
	ListAPIKeys(ctx context.Context, req *query.ListAPIKeysRequest) (*model.APIKeyResult, error)
	// GetAPIKey returns API key by ID
	GetAPIKey(ctx context.Context, orgID, id uint64) (*model.APIKey, error)
}

// OrgsDb defines an interface for CRUD operations on Orgs
type OrgsDb interface {
	OrgsReadonlyDb

	// LoginUser returns User
	LoginUser(ctx context.Context, login *model.Login) (*model.Login, *model.User, error)
	// DeleteUserByEmail deletes user and logins
	DeleteUserByEmail(ctx context.Context, email string) (map[string]int64, error)
	// DeleteUser deletes user and logins by user ID
	DeleteUser(ctx context.Context, id uint64) (map[string]int64, error)
	// UpdateUser updates a user's profile
	UpdateUser(ctx context.Context, id uint64, name string, emailVerified bool) (*model.User, error)
	// DeleteLogin deletes a single login by ID
	DeleteLogin(ctx context.Context, id uint64) (int64, error)

	// RegisterOrg registers a new org
	RegisterOrg(ctx context.Context, org *model.Org, ownerID uint64) (*model.Org, error)
	// UpdateOrg updates an org
	UpdateOrg(ctx context.Context, req *query.UpdateOrgRequest) (*model.Org, error)
	// DeleteOrg deletes an org and all its projects and members
	DeleteOrg(ctx context.Context, id uint64) (map[string]int64, error)

	// RegisterProject creates a project in an org
	RegisterProject(ctx context.Context, project *model.Project) (*model.Project, error)
	// UpdateProject updates a project's name, description or status
	UpdateProject(ctx context.Context, req *query.UpdateProjectRequest) (*model.Project, error)

	// AddMember adds a member to an org (empty ProjectID) or to a project
	AddMember(ctx context.Context, member *model.Membership) (*model.Membership, error)
	// UpdateMemberRole updates the role of a membership at the given scope
	UpdateMemberRole(ctx context.Context, req *query.UpdateMemberRoleRequest) (*model.Membership, error)
	// DeleteMember deletes memberships at the requested scope
	DeleteMember(ctx context.Context, r *query.DeleteMemberRequest) (int64, error)

	// CreateInvite creates or updates an invite for a user to join an org
	// (empty ProjectID) or a project
	CreateInvite(ctx context.Context, invite *model.Invite) (*model.Invite, error)
	// DeleteInviteByID deletes an invite by ID
	DeleteInviteByID(ctx context.Context, id uint64) (int64, error)
	// DeleteInvite deletes invites at the requested scope
	DeleteInvite(ctx context.Context, r *query.DeleteInviteRequest) (int64, error)
	// AcceptInvite accepts an org invite for a user
	AcceptInvite(ctx context.Context, inviteID, userID uint64) (*model.Membership, error)
	// AcceptInvites moves invites to membership
	AcceptInvites(ctx context.Context, user *model.User) (int64, error)

	// CreateEvent returns new Event
	CreateEvent(ctx context.Context, m *model.Event) (*model.Event, error)
	// TryCreateEvent creates the event asynchronously and logs failures
	TryCreateEvent(evt *model.Event)

	// UseAPIKey increments the used count and sets the used at time
	UseAPIKey(ctx context.Context, orgID, id uint64) (*model.APIKey, error)
	// RegisterAPIKey inserts a new API key into the database
	RegisterAPIKey(ctx context.Context, m *model.APIKey) (*model.APIKey, error)
	// UpdateAPIKey updates an API key
	// DeleteAPIKey deletes an API key
	DeleteAPIKey(ctx context.Context, orgID, id uint64) (int64, error)
	// TODO: implement UpdateAPIKey: label, scopes, metadata, expires_at
	// for now delete and create new
	// UpdateAPIKey(ctx context.Context, req *query.UpdateAPIKeyRequest) (*model.APIKey, error)
}

// Provider provides complete DB access
type Provider interface {
	xdb.Provider

	OrgsDb
}

// New creates a Provider instance
func New(dataSourceName, migrationsDir string, forceVersion, migrateVersion int, idGen flake.IDGenerator) (Provider, error) {
	var migrateCfg *xdb.MigrationConfig
	if migrationsDir != "" {
		migrateCfg = &xdb.MigrationConfig{
			ForceVersion:   forceVersion,
			MigrateVersion: migrateVersion,
			Source:         migrationsDir,
		}
	}

	p, err := xdb.NewProvider(dataSourceName, "", idGen, migrateCfg)
	if err != nil {
		return nil, err
	}

	return pgsql.New(p)
}
