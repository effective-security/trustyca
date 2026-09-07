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

// CanAssumeRoles specifies which roles a caller role may satisfy.
// Role_Enum values are sequential, not bit flags, so membership is
// checked by set inclusion rather than bitwise OR.
var CanAssumeRoles = map[pb.Role_Enum][]pb.Role_Enum{
	pb.Role_APIKey:  {pb.Role_APIKey},
	pb.Role_User:    {pb.Role_User},
	pb.Role_Support: {pb.Role_Support, pb.Role_User},
	pb.Role_Admin:   {pb.Role_Admin, pb.Role_Support, pb.Role_User},
	pb.Role_Owner:   {pb.Role_Owner, pb.Role_Admin, pb.Role_Support, pb.Role_User},
}

// the same as in pb but with lowercase
var RoleEnumValue = map[string]pb.Role_Enum{
	"apikey":  pb.Role_APIKey,
	"APIKey":  pb.Role_APIKey,
	"user":    pb.Role_User,
	"User":    pb.Role_User,
	"support": pb.Role_Support,
	"Support": pb.Role_Support,
	"admin":   pb.Role_Admin,
	"Admin":   pb.Role_Admin,
	"owner":   pb.Role_Owner,
	"Owner":   pb.Role_Owner,
}

// the same as in pb but lowercase
var MembershipRoleEnumValue = map[string]pb.Role_Enum{
	"user": pb.Role_User,
	"User": pb.Role_User,
	// Admin must be explicitly added to Members
	//	"admin":    pb.Role_Admin,
}

// CanAssumeRole returns true if a caller has access to assumed role
func CanAssumeRole(callerRole pb.Role_Enum, allowedRoles []string) bool {
	callerCan := CanAssumeRoles[callerRole]
	for _, allowedRole := range allowedRoles {
		role := RoleEnumValue[allowedRole]
		for _, can := range callerCan {
			if can == role {
				return true
			}
		}
	}
	return false
}

// RoleChecker interface specifies role checker
type RoleChecker interface {
	// CheckRole returns an error if a caller does not have access
	CheckRole(ctx context.Context, orgID string, callerID xdb.ID, allowedRoles ...string) (*model.MembershipInfo, error)
	// InvalidateCache invalidates the cache for the given user ID
	InvalidateCache(ctx context.Context, userID string)
}

type MembershipProvider interface {
	// ListMemberships lists memberships
	ListMemberships(ctx context.Context, req *query.ListMembershipsRequest) (model.MembershipInfoSlice, error)
}

const membershipCacheTTL = time.Minute * 3

type checkRole struct {
	membership MembershipProvider
	cache      cache.Provider
}

func NewRoleChecker(membership MembershipProvider) RoleChecker {
	return &checkRole{
		membership: membership,
		cache:      cache.NewMemoryProvider("authz"),
	}
}

// CheckRole returns an error if a caller does not have access
func (p *checkRole) CheckRole(ctx context.Context, orgID string, callerID xdb.ID, allowedRoles ...string) (*model.MembershipInfo, error) {
	oid, err := xdb.ParseID(orgID)
	if err != nil {
		return nil, errors.WithMessage(err, "invalid org ID")
	}

	key := "/memberships/" + callerID.String()
	var memberships model.MembershipInfoSlice

	var cached model.MembershipInfoSlice
	if err := p.cache.Get(ctx, key, &cached); err == nil {
		memberships = cached
	} else {
		memberships, err = p.membership.ListMemberships(ctx, &query.ListMembershipsRequest{
			UserID:    callerID.UInt64(),
			OrgStatus: pb.ItemStatus_Active,
		})
		if err != nil {
			return nil, errors.WithMessage(err, "unable to get user memberships")
		}
		_ = p.cache.Set(ctx, key, memberships, membershipCacheTTL)
	}

	var found *model.MembershipInfo
	for idx, m := range memberships {
		if m.OrgID.UInt64() == oid.UInt64() && m.UserID.UInt64() == callerID.UInt64() {
			found = memberships[idx]
			break
		}
	}
	if found != nil && CanAssumeRole(found.Role, allowedRoles) {
		return found, nil
	}
	return nil, errors.New("insufficient role")
}

// InvalidateCache invalidates the cache for the given user ID
func (p *checkRole) InvalidateCache(ctx context.Context, userID string) {
	key := "/memberships/" + userID
	_ = p.cache.Delete(ctx, key)
}
