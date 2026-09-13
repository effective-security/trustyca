package authctx

import (
	"context"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/pkg/cache"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/xdb"
)

var (
	// ErrInsufficientRole is returned when none of the caller's roles at the
	// requested scope can assume an allowed role
	ErrInsufficientRole = errors.New("insufficient role")
	// ErrAccessDenied is returned when the project does not belong to the
	// org or is inactive, so that callers do not leak project existence
	ErrAccessDenied = errors.New("access denied")
	// ErrOrgNotSelected is returned when the token has no selected org
	ErrOrgNotSelected = errors.New("org not selected")
)

// GrantsProvider provides memberships and projects to the authorizer.
// It is plain CRUD: the DB layer is not aware of authorization.
type GrantsProvider interface {
	// ListMemberships lists memberships
	ListMemberships(ctx context.Context, req *query.ListMembershipsRequest) (model.MembershipInfoSlice, error)
	// GetProject returns Project by ID
	GetProject(ctx context.Context, id uint64) (*model.Project, error)
}

// Authorizer resolves the caller's explicit grants and checks roles.
//
// Grants are cached per user with a bounded TTL; membership mutations must
// call InvalidateUser after commit. Sensitive operations that require
// immediate revocation should bypass the cache with an authoritative check.
type Authorizer interface {
	// Grants returns the explicit grants of the user in the org.
	// A user without grants gets empty Grants, not an error.
	Grants(ctx context.Context, orgID, userID xdb.ID) (*Grants, error)
	// Project returns the active project of the org.
	// It returns ErrAccessDenied when the project belongs to another org or
	// is inactive.
	Project(ctx context.Context, orgID, projectID xdb.ID) (*model.Project, error)
	// CheckRole returns the caller's role at the scope that can assume one of
	// the allowed roles: the org-wide role at org scope (projectID 0), the
	// org-wide or the project role at project scope. It returns
	// ErrInsufficientRole when no role can, and ErrAccessDenied when the
	// project is not an active project of the org.
	CheckRole(ctx context.Context, orgID, projectID, userID xdb.ID, allowedRoles ...string) (pb.Role_Enum, *Grants, error)
	// InvalidateUser invalidates the cached grants of the user
	InvalidateUser(ctx context.Context, userID string)
	// InvalidateProject invalidates the cached project
	InvalidateProject(ctx context.Context, projectID string)
}

// grantsCacheTTL bounds the staleness of cached grants and projects
const grantsCacheTTL = time.Minute * 3

type authorizer struct {
	provider GrantsProvider
	cache    cache.Provider
}

// NewAuthorizer returns Authorizer backed by the grants provider
func NewAuthorizer(provider GrantsProvider) Authorizer {
	return &authorizer{
		provider: provider,
		cache:    cache.NewMemoryProvider("authz"),
	}
}

func membershipsCacheKey(userID string) string {
	return "/memberships/" + userID
}

func projectCacheKey(projectID string) string {
	return "/projects/" + projectID
}

// Grants returns the explicit grants of the user in the org
func (a *authorizer) Grants(ctx context.Context, orgID, userID xdb.ID) (*Grants, error) {
	if orgID.UInt64() == 0 {
		return nil, ErrOrgNotSelected
	}
	memberships, err := a.getMemberships(ctx, userID)
	if err != nil {
		return nil, err
	}
	return GrantsFromMemberships(memberships, orgID, userID), nil
}

// Project returns the active project of the org
func (a *authorizer) Project(ctx context.Context, orgID, projectID xdb.ID) (*model.Project, error) {
	if orgID.UInt64() == 0 {
		return nil, ErrOrgNotSelected
	}
	project, err := a.getProject(ctx, projectID)
	if err != nil {
		if xdb.IsNotFoundError(err) {
			return nil, ErrAccessDenied
		}
		return nil, errors.WithMessage(err, "unable to get project")
	}
	if project.OrgID.UInt64() != orgID.UInt64() || project.Status != pb.ItemStatus_Active {
		return nil, ErrAccessDenied
	}
	return project, nil
}

// CheckRole returns the caller's role at the scope that can assume one of
// the allowed roles
func (a *authorizer) CheckRole(ctx context.Context, orgID, projectID, userID xdb.ID, allowedRoles ...string) (pb.Role_Enum, *Grants, error) {
	if projectID.UInt64() != 0 {
		if _, err := a.Project(ctx, orgID, projectID); err != nil {
			return pb.Role_None, nil, err
		}
	}
	grants, err := a.Grants(ctx, orgID, userID)
	if err != nil {
		return pb.Role_None, nil, err
	}
	role := grants.HighestRole(projectID.UInt64(), allowedRoles)
	if role == pb.Role_None {
		return pb.Role_None, grants, ErrInsufficientRole
	}
	return role, grants, nil
}

func (a *authorizer) getMemberships(ctx context.Context, userID xdb.ID) (model.MembershipInfoSlice, error) {
	key := membershipsCacheKey(userID.String())

	var cached model.MembershipInfoSlice
	if err := a.cache.Get(ctx, key, &cached); err == nil {
		return cached, nil
	}

	memberships, err := a.provider.ListMemberships(ctx, &query.ListMembershipsRequest{
		UserID:    userID.UInt64(),
		OrgStatus: pb.ItemStatus_Active,
	})
	if err != nil {
		return nil, errors.WithMessage(err, "unable to get user memberships")
	}
	_ = a.cache.Set(ctx, key, memberships, grantsCacheTTL)
	return memberships, nil
}

func (a *authorizer) getProject(ctx context.Context, projectID xdb.ID) (*model.Project, error) {
	key := projectCacheKey(projectID.String())

	var cached model.Project
	if err := a.cache.Get(ctx, key, &cached); err == nil {
		return &cached, nil
	}

	project, err := a.provider.GetProject(ctx, projectID.UInt64())
	if err != nil {
		return nil, err
	}
	_ = a.cache.Set(ctx, key, project, grantsCacheTTL)
	return project, nil
}

// InvalidateUser invalidates the cached grants of the user
func (a *authorizer) InvalidateUser(ctx context.Context, userID string) {
	_ = a.cache.Delete(ctx, membershipsCacheKey(userID))
}

// InvalidateProject invalidates the cached project
func (a *authorizer) InvalidateProject(ctx context.Context, projectID string) {
	_ = a.cache.Delete(ctx, projectCacheKey(projectID))
}
