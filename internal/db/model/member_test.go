package model

import (
	"testing"
	"time"

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

func TestMembershipInfoSliceFinders(t *testing.T) {
	m := MembershipInfoSlice{
		{ID: xdb.NewID(1), OrgID: xdb.NewID(100), UserID: xdb.NewID(3), Email: "user@example.com", Role: pb.Role_Admin},
		{ID: xdb.NewID(2), OrgID: xdb.NewID(100), ProjectID: xdb.NewID(201), UserID: xdb.NewID(3), Email: "user@example.com", Role: pb.Role_User},
		{ID: xdb.NewID(3), OrgID: xdb.NewID(100), UserID: xdb.NewID(4), Email: "owner@example.com", Role: pb.Role_Owner},
		{ID: xdb.NewID(4), OrgID: xdb.NewID(101), UserID: xdb.NewID(3), Email: "user@example.com", Role: pb.Role_Owner},
	}
	member := m.FindMemberByUserID(3, 0)
	require.NotNil(t, member)
	assert.Equal(t, m[0], member)
	assert.Equal(t, pb.Scope_Org, member.Scope())

	member = m.FindMemberByUserID(3, 201)
	require.NotNil(t, member)
	assert.Equal(t, m[1], member)
	assert.Equal(t, pb.Scope_Project, member.Scope())

	assert.Nil(t, m.FindMemberByUserID(3, 202))
	assert.Nil(t, m.FindMemberByUserID(5, 0))

	member = m.FindMemberByEmail("user@example.com", 201)
	require.NotNil(t, member)
	assert.Equal(t, m[1], member)
	assert.Nil(t, m.FindMemberByEmail("user3@example.com", 0))

	assert.Len(t, m.FilterByOrg(100), 3)
	assert.Len(t, m.FilterByOrg(102), 0)
	assert.Equal(t, []xdb.ID{xdb.NewID(100), xdb.NewID(101)}, m.OrgIDs())
	assert.Equal(t, 1, m.CountOrgRole(100, pb.Role_Owner))
	assert.Equal(t, 0, m.CountOrgRole(100, pb.Role_Viewer))
	assert.Equal(t, 1, m.CountOrgRole(101, pb.Role_Owner))

	assert.Equal(t, pb.Scope_Org, ScopeOf(xdb.ID{}))
	assert.Equal(t, pb.Scope_Project, ScopeOf(xdb.NewID(1)))

	pm := m[1].Pb()
	assert.Equal(t, pb.Scope_Project, pm.Scope)
	assert.Equal(t, "201", pm.ProjectID)
}

func TestInviteSlice(t *testing.T) {
	past := xdb.Time(time.Now().Add(-time.Hour))
	future := xdb.Time(time.Now().Add(time.Hour))
	invites := InviteSlice{
		{ID: xdb.NewID(1), OrgID: xdb.NewID(100), Email: "a@example.com", Role: pb.Role_User, ExpiresAt: future},
		{ID: xdb.NewID(2), OrgID: xdb.NewID(100), ProjectID: xdb.NewID(201), Email: "b@example.com", Role: pb.Role_User, ExpiresAt: past},
		{ID: xdb.NewID(3), OrgID: xdb.NewID(100), Email: "c@example.com", Role: pb.Role_User},
	}
	org := invites.FilterByProject(0)
	require.Len(t, org, 2)
	assert.Equal(t, "a@example.com", org[0].Email)
	assert.Equal(t, pb.Scope_Org, org[0].Scope())

	project := invites.FilterByProject(201)
	require.Len(t, project, 1)
	assert.Equal(t, "b@example.com", project[0].Email)
	assert.Equal(t, pb.Scope_Project, project[0].Pb().Scope)
	assert.Equal(t, "201", project[0].Pb().ProjectID)
	assert.Empty(t, invites.FilterByProject(999))

	now := time.Now()
	assert.False(t, invites[0].IsExpired(now))
	assert.True(t, invites[1].IsExpired(now))
	assert.False(t, invites[2].IsExpired(now), "no expiry never expires")
	assert.NotEmpty(t, invites[0].Pb().ExpiresAt)
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
	project := &Project{
		ID:    xdb.NewID(5),
		OrgID: org.ID,
		Alias: "project_alias",
		Name:  "Project Name",
	}
	membership := &Membership{
		ID:        xdb.NewID(3),
		OrgID:     org.ID,
		UserID:    user.ID,
		Role:      pb.Role_Admin,
		CreatedAt: xdb.ParseTime("2020-01-01"),
	}
	pm := membership.Pb(org, nil, user)
	assert.Equal(t, membership.ID.String(), pm.ID)
	assert.Equal(t, org.ID.String(), pm.OrgID)
	assert.Equal(t, org.Alias, pm.OrgAlias)
	assert.Equal(t, org.Name, pm.OrgName)
	assert.Equal(t, user.ID.String(), pm.UserID)
	assert.Equal(t, user.Email, pm.Email)
	assert.Equal(t, user.Name, pm.Name)
	assert.Equal(t, membership.Role, pm.Role)
	assert.Equal(t, membership.CreatedAt.String(), pm.CreatedAt)
	assert.Equal(t, pb.Scope_Org, pm.Scope)
	assert.Empty(t, pm.ProjectID)

	membership.ProjectID = project.ID
	pm = membership.Pb(org, project, user)
	assert.Equal(t, pb.Scope_Project, pm.Scope)
	assert.Equal(t, project.ID.String(), pm.ProjectID)
	assert.Equal(t, project.Alias, pm.ProjectAlias)
	assert.Equal(t, project.Name, pm.ProjectName)
}

func TestProjectValidate(t *testing.T) {
	p := &Project{OrgID: xdb.NewID(1), Alias: "payments", Name: "Payments"}
	assert.NoError(t, p.Validate())
	assert.EqualError(t, (&Project{Alias: "a", Name: "n"}).Validate(), "invalid org_id")
	assert.EqualError(t, (&Project{OrgID: xdb.NewID(1), Alias: " a", Name: "n"}).Validate(), `invalid alias: " a"`)
	assert.EqualError(t, (&Project{OrgID: xdb.NewID(1), Alias: "a"}).Validate(), `invalid name: ""`)

	pm := p.Pb()
	assert.Equal(t, "payments", pm.Alias)
	assert.Equal(t, "1", pm.OrgID)
}
