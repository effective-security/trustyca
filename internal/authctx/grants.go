package authctx

import (
	"sort"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/xdb"
)

// Grants are the explicit grants of a user in one org, as stored in the
// membership table: an optional org-wide role and a role per project.
//
// Grants are additive. At org scope the caller acts with the org-wide role.
// At project scope the caller acts with the org-wide role, inherited by every
// project of the org, and with the project role; a method is allowed when
// either role can assume one of its allowed roles. A user with project grants
// only is a derived org Viewer: it may select the org and read its summary,
// but inherits nothing in other projects.
type Grants struct {
	OrgID  xdb.ID
	UserID xdb.ID
	// OrgRole is the explicit org-wide role, None when absent
	OrgRole pb.Role_Enum
	// ProjectRoles maps project ID to the explicit project role
	ProjectRoles map[uint64]pb.Role_Enum
}

// GrantsFromMemberships builds the grants of the user in the org from
// membership rows. Rows of other orgs and users are ignored.
func GrantsFromMemberships(rows model.MembershipInfoSlice, orgID, userID xdb.ID) *Grants {
	g := &Grants{
		OrgID:        orgID,
		UserID:       userID,
		ProjectRoles: map[uint64]pb.Role_Enum{},
	}
	for _, m := range rows {
		if m.OrgID.UInt64() != orgID.UInt64() || m.UserID.UInt64() != userID.UInt64() {
			continue
		}
		if pid := m.ProjectID.UInt64(); pid != 0 {
			g.ProjectRoles[pid] = m.Role
		} else {
			g.OrgRole = m.Role
		}
	}
	return g
}

// IsMember returns true if the user has any grant in the org
func (g *Grants) IsMember() bool {
	return g != nil && (g.OrgRole != pb.Role_None || len(g.ProjectRoles) > 0)
}

// ResolvedOrgRole returns the org role and how it was resolved:
// the explicit org-wide role (Direct), or Viewer when the user has project
// grants only (Project). None when the user is not a member.
func (g *Grants) ResolvedOrgRole() (pb.Role_Enum, pb.RoleSource_Enum) {
	if g == nil {
		return pb.Role_None, pb.RoleSource_Unknown
	}
	if g.OrgRole != pb.Role_None {
		return g.OrgRole, pb.RoleSource_Direct
	}
	if len(g.ProjectRoles) > 0 {
		return pb.Role_Viewer, pb.RoleSource_Project
	}
	return pb.Role_None, pb.RoleSource_Unknown
}

// OrgAccess returns the resolved org access for the discovery API
func (g *Grants) OrgAccess() *pb.OrgAccess {
	role, source := g.ResolvedOrgRole()
	return &pb.OrgAccess{
		OrgID:        g.OrgID.String(),
		Role:         role,
		RoleSource:   source,
		ExplicitRole: g.OrgRole,
	}
}

// Roles returns the roles the user acts with at the scope:
// at org scope (projectID 0) the resolved org role; at project scope the
// explicit org-wide role and the project role. The derived org Viewer is
// not inherited by projects.
func (g *Grants) Roles(projectID uint64) []pb.Role_Enum {
	if g == nil {
		return nil
	}
	var roles []pb.Role_Enum
	if projectID == 0 {
		if role, _ := g.ResolvedOrgRole(); role != pb.Role_None {
			roles = append(roles, role)
		}
		return roles
	}
	if g.OrgRole != pb.Role_None {
		roles = append(roles, g.OrgRole)
	}
	if role, ok := g.ProjectRoles[projectID]; ok {
		roles = append(roles, role)
	}
	return roles
}

// HighestRole returns the user's role at the scope that can assume one of
// the allowed roles, preferring the org-wide role; None when no role can.
// An empty allowed list accepts any role at the scope.
func (g *Grants) HighestRole(projectID uint64, allowedRoles []string) pb.Role_Enum {
	for _, role := range g.Roles(projectID) {
		if len(allowedRoles) == 0 || CanAssumeRole(role, allowedRoles) {
			return role
		}
	}
	return pb.Role_None
}

// HasProjectAccess returns true if the user has any role at the project
func (g *Grants) HasProjectAccess(projectID uint64) bool {
	return len(g.Roles(projectID)) > 0
}

// CanListAllProjects returns true if the user may list every project of the
// org: any explicit org-wide role. Project-only members list their projects.
func (g *Grants) CanListAllProjects() bool {
	return g != nil && g.OrgRole != pb.Role_None
}

// GrantedProjectIDs returns the IDs of the projects with an explicit grant,
// sorted
func (g *Grants) GrantedProjectIDs() []uint64 {
	if g == nil {
		return nil
	}
	res := make([]uint64, 0, len(g.ProjectRoles))
	for id := range g.ProjectRoles {
		res = append(res, id)
	}
	sort.Slice(res, func(i, j int) bool { return res[i] < res[j] })
	return res
}

// CanGrantOrgRole returns true if the user may grant (or revoke) the role
// org-wide. An org Admin may grant any org role except Owner; only an Owner
// may grant Owner. Project grants never allow org-wide grants.
func (g *Grants) CanGrantOrgRole(role pb.Role_Enum) bool {
	if g == nil || !IsOrgRole(role) || g.OrgRole == pb.Role_None {
		return false
	}
	if g.OrgRole == pb.Role_Owner {
		return true
	}
	return role != pb.Role_Owner && CanAssumeRole(g.OrgRole, []string{pb.Role_Admin.String()})
}

// CanGrantProjectRole returns true if the user may grant (or revoke) the role
// in the project: the role must be a project role and the user must be an
// Admin in the project, org-wide or explicitly
func (g *Grants) CanGrantProjectRole(projectID uint64, role pb.Role_Enum) bool {
	if g == nil || !IsProjectRole(role) {
		return false
	}
	return g.HighestRole(projectID, []string{pb.Role_Admin.String()}) != pb.Role_None
}
