package model

import (
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/xdb"
)

// ScopeOf returns the grant scope for the project ID:
// Org when the project ID is empty, Project otherwise.
func ScopeOf(projectID xdb.ID) pb.Scope_Enum {
	if projectID.UInt64() == 0 {
		return pb.Scope_Org
	}
	return pb.Scope_Project
}

// Validate returns error if the model is not valid
func (m *Membership) Validate() error {
	if m.OrgID.UInt64() == 0 {
		return errors.Errorf("invalid org_id")
	}
	if m.UserID.UInt64() == 0 {
		return errors.Errorf("invalid user_id")
	}
	if m.Role == 0 {
		return errors.Errorf("invalid role")
	}
	return nil
}

// Scope returns the grant scope
func (m *Membership) Scope() pb.Scope_Enum {
	return ScopeOf(m.ProjectID)
}

// Scope returns the grant scope
func (m *MembershipInfo) Scope() pb.Scope_Enum {
	return ScopeOf(m.ProjectID)
}

// Pb converts model to proto
func (m *MembershipInfo) Pb() *pb.Membership {
	return &pb.Membership{
		ID:           m.ID.String(),
		OrgID:        m.OrgID.String(),
		OrgAlias:     m.OrgAlias,
		OrgName:      m.OrgName,
		UserID:       m.UserID.String(),
		Email:        m.Email,
		Name:         m.Name,
		Role:         m.Role,
		CreatedAt:    m.CreatedAt.String(),
		Scope:        m.Scope(),
		ProjectID:    m.ProjectID.String(),
		ProjectAlias: m.ProjectAlias,
		ProjectName:  m.ProjectName,
	}
}

// Pb converts slice of model to proto
func (m MembershipInfoSlice) Pb() []*pb.Membership {
	res := make([]*pb.Membership, 0, len(m))
	for _, v := range m {
		res = append(res, v.Pb())
	}
	return res
}

// FindMemberByUserID finds a grant by user ID at the given scope:
// projectID 0 matches the org-wide grant, otherwise the project grant.
func (m MembershipInfoSlice) FindMemberByUserID(userID, projectID uint64) *MembershipInfo {
	for _, v := range m {
		if v.UserID.UInt64() == userID && v.ProjectID.UInt64() == projectID {
			return v
		}
	}
	return nil
}

// FindMemberByEmail finds a grant by email at the given scope:
// projectID 0 matches the org-wide grant, otherwise the project grant.
func (m MembershipInfoSlice) FindMemberByEmail(email string, projectID uint64) *MembershipInfo {
	for _, v := range m {
		if v.Email == email && v.ProjectID.UInt64() == projectID {
			return v
		}
	}
	return nil
}

// FilterByOrg returns the grants of the org
func (m MembershipInfoSlice) FilterByOrg(orgID uint64) MembershipInfoSlice {
	res := make(MembershipInfoSlice, 0, len(m))
	for _, v := range m {
		if v.OrgID.UInt64() == orgID {
			res = append(res, v)
		}
	}
	return res
}

// OrgIDs returns the distinct org IDs of the grants, in first-seen order
func (m MembershipInfoSlice) OrgIDs() []xdb.ID {
	seen := map[uint64]bool{}
	var res []xdb.ID
	for _, v := range m {
		if id := v.OrgID.UInt64(); !seen[id] {
			seen[id] = true
			res = append(res, v.OrgID)
		}
	}
	return res
}

// CountOrgRole returns the number of org-wide grants with the role
func (m MembershipInfoSlice) CountOrgRole(orgID uint64, role pb.Role_Enum) int {
	n := 0
	for _, v := range m {
		if v.OrgID.UInt64() == orgID && v.ProjectID.UInt64() == 0 && v.Role == role {
			n++
		}
	}
	return n
}

// Pb converts model to proto
func (m *Membership) Pb(org *Org, project *Project, user *User) *pb.Membership {
	res := &pb.Membership{
		ID:        m.ID.String(),
		OrgID:     m.OrgID.String(),
		UserID:    m.UserID.String(),
		Role:      m.Role,
		CreatedAt: m.CreatedAt.String(),
		Scope:     m.Scope(),
		ProjectID: m.ProjectID.String(),
	}
	if org != nil {
		res.OrgAlias = org.Alias
		res.OrgName = org.Name
	}
	if project != nil {
		res.ProjectAlias = project.Alias
		res.ProjectName = project.Name
	}
	if user != nil {
		res.Email = user.Email
		res.Name = user.Name
	}
	return res
}

// Scope returns the invite scope
func (m *Invite) Scope() pb.Scope_Enum {
	return ScopeOf(m.ProjectID)
}

// IsExpired returns true if the invite has an expiry in the past
func (m *Invite) IsExpired(now time.Time) bool {
	t := m.ExpiresAt.UTC()
	return !t.IsZero() && t.Before(now)
}

// Pb converts model to proto
func (m *Invite) Pb() *pb.Invite {
	return &pb.Invite{
		ID:        m.ID.String(),
		OrgID:     m.OrgID.String(),
		InviterID: m.InviterID.String(),
		Email:     m.Email,
		Role:      m.Role,
		CreatedAt: m.CreatedAt.String(),
		Scope:     m.Scope(),
		ProjectID: m.ProjectID.String(),
		ExpiresAt: m.ExpiresAt.String(),
	}
}

// Pb converts slice of model to proto
func (m InviteSlice) Pb() []*pb.Invite {
	res := make([]*pb.Invite, 0, len(m))
	for _, v := range m {
		res = append(res, v.Pb())
	}
	return res
}

// FilterByProject returns invites at the given scope:
// projectID 0 returns org-wide invites, otherwise the invites of the project.
func (m InviteSlice) FilterByProject(projectID uint64) InviteSlice {
	res := make(InviteSlice, 0, len(m))
	for _, v := range m {
		if v.ProjectID.UInt64() == projectID {
			res = append(res, v)
		}
	}
	return res
}
