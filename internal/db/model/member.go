package model

import (
	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
)

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

// Pb converts model to proto
func (m *MembershipInfo) Pb() *pb.Membership {
	return &pb.Membership{
		ID:        m.ID.String(),
		OrgID:     m.OrgID.String(),
		OrgAlias:  m.OrgAlias,
		OrgName:   m.OrgName,
		UserID:    m.UserID.String(),
		Email:     m.Email,
		Name:      m.Name,
		Role:      m.Role,
		CreatedAt: m.CreatedAt.String(),
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

// FindMemberByUserID finds a member by user ID
func (m MembershipInfoSlice) FindMemberByUserID(userID uint64) *MembershipInfo {
	for _, v := range m {
		if v.UserID.UInt64() == userID {
			return v
		}
	}
	return nil
}

// FindMemberByEmail finds a member by email
func (m MembershipInfoSlice) FindMemberByEmail(email string) *MembershipInfo {
	for _, v := range m {
		if v.Email == email {
			return v
		}
	}
	return nil
}

// Pb converts model to proto
func (m *Membership) Pb(org *Org, user *User) *pb.Membership {
	return &pb.Membership{
		ID:        m.ID.String(),
		OrgID:     m.OrgID.String(),
		OrgAlias:  org.Alias,
		OrgName:   org.Name,
		UserID:    m.UserID.String(),
		Email:     user.Email,
		Name:      user.Name,
		Role:      m.Role,
		CreatedAt: m.CreatedAt.String(),
	}
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
