package model

import (
	"testing"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/xdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMembershipValidate(t *testing.T) {
	t.Parallel()
	tcases := []struct {
		name       string
		membership Membership
		err        string
	}{
		{
			name: "valid",
			membership: Membership{
				OrgID:  xdb.NewID(1),
				UserID: xdb.NewID(2),
				Role:   pb.Role_Owner,
			},
			err: "",
		},
		{
			name:       "invalid org_id",
			membership: Membership{UserID: xdb.NewID(2), Role: pb.Role_Owner},
			err:        "invalid org_id",
		},
		{
			name:       "invalid user_id",
			membership: Membership{OrgID: xdb.NewID(1), Role: pb.Role_Owner},
			err:        "invalid user_id",
		},
		{
			name:       "invalid role",
			membership: Membership{OrgID: xdb.NewID(1), UserID: xdb.NewID(2)},
			err:        "invalid role",
		},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.membership.Validate()
			if tc.err != "" {
				require.Error(t, err)
				assert.Equal(t, tc.err, err.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMembershipInfoPb(t *testing.T) {
	m := MembershipInfo{
		ID:        xdb.NewID(1),
		OrgID:     xdb.NewID(2),
		OrgAlias:  "cp_alias",
		OrgName:   "Project Name",
		UserID:    xdb.NewID(3),
		Email:     "user@example.com",
		Name:      "User Name",
		Role:      pb.Role_Admin,
		CreatedAt: xdb.ParseTime("2020-01-01"),
	}
	pm := m.Pb()
	assert.Equal(t, m.ID.String(), pm.ID)
	assert.Equal(t, m.OrgID.String(), pm.OrgID)
	assert.Equal(t, m.OrgAlias, pm.OrgAlias)
	assert.Equal(t, m.OrgName, pm.OrgName)
	assert.Equal(t, m.UserID.String(), pm.UserID)
	assert.Equal(t, m.Email, pm.Email)
	assert.Equal(t, m.Name, pm.Name)
	assert.Equal(t, m.Role, pm.Role)
	assert.Equal(t, m.CreatedAt.String(), pm.CreatedAt)
}

func TestMembershipInfoSliceFindMemberByUserID(t *testing.T) {
	m := MembershipInfoSlice{
		{ID: xdb.NewID(1), OrgID: xdb.NewID(2), UserID: xdb.NewID(3), Email: "user@example.com", Name: "User Name", Role: pb.Role_Admin},
		{ID: xdb.NewID(2), OrgID: xdb.NewID(2), UserID: xdb.NewID(4), Email: "user2@example.com", Name: "User Name 2", Role: pb.Role_User},
	}
	member := m.FindMemberByUserID(3)
	require.NotNil(t, member)
	assert.Equal(t, m[0], member)

	member = m.FindMemberByUserID(5)
	assert.Nil(t, member)

	member = m.FindMemberByEmail("user@example.com")
	require.NotNil(t, member)
	assert.Equal(t, m[0], member)

	member = m.FindMemberByEmail("user3@example.com")
	assert.Nil(t, member)
}

func TestMembershipPb(t *testing.T) {
	org := &Org{
		ID:    xdb.NewID(1),
		Alias: "org_alias",
		Name:  "Org Name",
	}
	user := &User{
		ID:    xdb.NewID(2),
		Email: "user@example.com",
		Name:  "User Name",
	}
	membership := &Membership{
		ID:        xdb.NewID(3),
		OrgID:     org.ID,
		UserID:    user.ID,
		Role:      pb.Role_Admin,
		CreatedAt: xdb.ParseTime("2020-01-01"),
	}
	pm := membership.Pb(org, user)
	assert.Equal(t, membership.ID.String(), pm.ID)
	assert.Equal(t, org.ID.String(), pm.OrgID)
	assert.Equal(t, org.Alias, pm.OrgAlias)
	assert.Equal(t, org.Name, pm.OrgName)
	assert.Equal(t, user.ID.String(), pm.UserID)
	assert.Equal(t, user.Email, pm.Email)
	assert.Equal(t, user.Name, pm.Name)
	assert.Equal(t, membership.Role, pm.Role)
	assert.Equal(t, membership.CreatedAt.String(), pm.CreatedAt)
}

func TestMembershipInfoSlicePb(t *testing.T) {
	m := MembershipInfoSlice{
		{ID: xdb.NewID(1), OrgID: xdb.NewID(2), UserID: xdb.NewID(3), Email: "user@example.com", Name: "User Name", Role: pb.Role_Admin},
		{ID: xdb.NewID(2), OrgID: xdb.NewID(2), UserID: xdb.NewID(4), Email: "user2@example.com", Name: "User Name 2", Role: pb.Role_User},
	}
	pms := m.Pb()
	require.Len(t, pms, 2)
	assert.Equal(t, m[0].ID.String(), pms[0].ID)
	assert.Equal(t, m[0].Email, pms[0].Email)
	assert.Equal(t, m[1].ID.String(), pms[1].ID)
	assert.Equal(t, m[1].Role, pms[1].Role)
}

func TestInvitePb(t *testing.T) {
	invite := &Invite{
		ID:        xdb.NewID(1),
		OrgID:     xdb.NewID(2),
		InviterID: xdb.NewID(3),
		Email:     "invitee@example.com",
		Role:      pb.Role_User,
		CreatedAt: xdb.ParseTime("2020-01-01"),
	}
	pi := invite.Pb()
	assert.Equal(t, invite.ID.String(), pi.ID)
	assert.Equal(t, invite.OrgID.String(), pi.OrgID)
	assert.Equal(t, invite.InviterID.String(), pi.InviterID)
	assert.Equal(t, invite.Email, pi.Email)
	assert.Equal(t, invite.Role, pi.Role)
	assert.Equal(t, invite.CreatedAt.String(), pi.CreatedAt)

	invites := InviteSlice{invite}
	pis := invites.Pb()
	require.Len(t, pis, 1)
	assert.Equal(t, pi, pis[0])
}
