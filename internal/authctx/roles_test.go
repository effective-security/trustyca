package authctx_test

import (
	"testing"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/authctx"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/xdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_CanAssumeRole(t *testing.T) {
	t.Parallel()

	// allowed_roles are minimum roles: Viewer is denied for "User",
	// Security is allowed because it may assume User
	assert.False(t, authctx.CanAssumeRole(pb.Role_Viewer, []string{"User", "APIKey"}))
	assert.True(t, authctx.CanAssumeRole(pb.Role_Security, []string{"User", "APIKey"}))
	assert.True(t, authctx.CanAssumeRole(pb.Role_APIKey, []string{"User", "APIKey"}))
	assert.True(t, authctx.CanAssumeRole(pb.Role_Owner, []string{"Admin"}))
	assert.True(t, authctx.CanAssumeRole(pb.Role_Admin, []string{"Security"}))
	assert.False(t, authctx.CanAssumeRole(pb.Role_Security, []string{"Admin"}))
	assert.False(t, authctx.CanAssumeRole(pb.Role_Billing, []string{"Support"}))
	assert.True(t, authctx.CanAssumeRole(pb.Role_Billing, []string{"viewer"}), "lowercase names are accepted")
	assert.False(t, authctx.CanAssumeRole(pb.Role_None, []string{"Viewer"}))
	assert.False(t, authctx.CanAssumeRole(pb.Role_Admin, nil))

	assert.True(t, authctx.AllowsRole([]string{"Viewer", "APIKey"}, pb.Role_APIKey))
	assert.False(t, authctx.AllowsRole([]string{"Admin"}, pb.Role_APIKey))

	assert.Equal(t, pb.Role_Admin, authctx.ParseRole("admin"))
	assert.Equal(t, pb.Role_Viewer, authctx.ParseRole("Viewer"))
	assert.Equal(t, pb.Role_APIKey, authctx.ParseRole("APIKey"))
	assert.Equal(t, pb.Role_None, authctx.ParseRole("root"))

	assert.True(t, authctx.IsOrgRole(pb.Role_Owner))
	assert.False(t, authctx.IsProjectRole(pb.Role_Owner))
	assert.False(t, authctx.IsProjectRole(pb.Role_Billing))
	assert.True(t, authctx.IsProjectRole(pb.Role_Admin))
	assert.False(t, authctx.IsOrgRole(pb.Role_APIKey))

	assert.Equal(t, "direct", authctx.RoleSourceClaim(pb.RoleSource_Direct))
	assert.Equal(t, "project", authctx.RoleSourceClaim(pb.RoleSource_Project))
	assert.Equal(t, "", authctx.RoleSourceClaim(pb.RoleSource_Unknown))

	// every grantable role has assumable roles
	for _, r := range authctx.OrgRoles {
		require.NotEmpty(t, authctx.CanAssumeRoles[r], r.String())
	}
}

func Test_Scopes(t *testing.T) {
	t.Parallel()

	assert.Equal(t, []string{"certs:issue", "certs:read"}, authctx.ParseScopes([]string{"certs:issue, certs:read", ""}))
	assert.Nil(t, authctx.ParseScopes(nil))

	granted := []string{"certs:read", "ca:*"}
	assert.True(t, authctx.HasScope(granted, "certs:read"))
	assert.True(t, authctx.HasScope(granted, "ca:write"))
	assert.False(t, authctx.HasScope(granted, "certs:issue"))
	assert.True(t, authctx.HasScope([]string{"*"}, "org:delete"))

	// every required scope must be granted
	assert.True(t, authctx.HasScopes(granted, []string{"certs:read", "ca:read"}))
	assert.False(t, authctx.HasScopes(granted, []string{"certs:read", "certs:issue"}))
	assert.True(t, authctx.HasScopes(granted, nil), "no required scopes")
	assert.False(t, authctx.HasScopes(nil, []string{"org:read"}))

	assert.True(t, authctx.IsKnownScope("certs:issue"))
	assert.True(t, authctx.IsKnownScope("certs:*"))
	assert.True(t, authctx.IsKnownScope("*"))
	assert.False(t, authctx.IsKnownScope("billing:write"))
	assert.False(t, authctx.IsKnownScope("foo:*"))
}

// specRows implement the spec example: org 100 with projects 201, 202;
// user 300: org User + project 201 Admin
// user 301: project 201 Admin only
// user 302: org Admin + project 201 Viewer
// user 303: org Viewer
// user 304: org Owner
// user 305: org Billing
var specRows = model.MembershipInfoSlice{
	{ID: xdb.NewID(1), OrgID: xdb.NewID(100), UserID: xdb.NewID(300), Role: pb.Role_User},
	{ID: xdb.NewID(2), OrgID: xdb.NewID(100), ProjectID: xdb.NewID(201), UserID: xdb.NewID(300), Role: pb.Role_Admin},
	{ID: xdb.NewID(3), OrgID: xdb.NewID(100), ProjectID: xdb.NewID(201), UserID: xdb.NewID(301), Role: pb.Role_Admin},
	{ID: xdb.NewID(4), OrgID: xdb.NewID(100), UserID: xdb.NewID(302), Role: pb.Role_Admin},
	{ID: xdb.NewID(5), OrgID: xdb.NewID(100), ProjectID: xdb.NewID(201), UserID: xdb.NewID(302), Role: pb.Role_Viewer},
	{ID: xdb.NewID(6), OrgID: xdb.NewID(100), UserID: xdb.NewID(303), Role: pb.Role_Viewer},
	{ID: xdb.NewID(7), OrgID: xdb.NewID(100), UserID: xdb.NewID(304), Role: pb.Role_Owner},
	{ID: xdb.NewID(8), OrgID: xdb.NewID(100), UserID: xdb.NewID(305), Role: pb.Role_Billing},
	// noise from another org
	{ID: xdb.NewID(9), OrgID: xdb.NewID(101), UserID: xdb.NewID(300), Role: pb.Role_Owner},
}

func grantsOf(user uint64) *authctx.Grants {
	return authctx.GrantsFromMemberships(specRows, xdb.NewID(100), xdb.NewID(user))
}

func Test_Grants(t *testing.T) {
	t.Parallel()

	g := grantsOf(300)
	assert.Equal(t, pb.Role_User, g.OrgRole)
	assert.Equal(t, map[uint64]pb.Role_Enum{201: pb.Role_Admin}, g.ProjectRoles)
	assert.True(t, g.IsMember())
	assert.Equal(t, []uint64{201}, g.GrantedProjectIDs())
	role, source := g.ResolvedOrgRole()
	assert.Equal(t, pb.Role_User, role)
	assert.Equal(t, pb.RoleSource_Direct, source)

	// roles at scope: org scope has the org role only; project 201 adds Admin
	assert.Equal(t, []pb.Role_Enum{pb.Role_User}, g.Roles(0))
	assert.Equal(t, []pb.Role_Enum{pb.Role_User, pb.Role_Admin}, g.Roles(201))
	assert.Equal(t, []pb.Role_Enum{pb.Role_User}, g.Roles(202))
	// spec: 300 is Admin in 201 (User ∪ Admin), User elsewhere, never org Admin
	assert.Equal(t, pb.Role_Admin, g.HighestRole(201, []string{"Admin"}))
	assert.Equal(t, pb.Role_None, g.HighestRole(202, []string{"Admin"}))
	assert.Equal(t, pb.Role_User, g.HighestRole(202, []string{"User"}))
	assert.Equal(t, pb.Role_None, g.HighestRole(0, []string{"Admin"}))
	assert.Equal(t, pb.Role_User, g.HighestRole(0, nil), "no allowed roles accepts any role")

	// spec: 301 project-only is a derived org Viewer with no other project access
	g = grantsOf(301)
	role, source = g.ResolvedOrgRole()
	assert.Equal(t, pb.Role_Viewer, role)
	assert.Equal(t, pb.RoleSource_Project, source)
	assert.Equal(t, []pb.Role_Enum{pb.Role_Viewer}, g.Roles(0))
	assert.Equal(t, []pb.Role_Enum{pb.Role_Admin}, g.Roles(201))
	assert.Empty(t, g.Roles(202), "derived Viewer is not inherited by projects")
	assert.False(t, g.HasProjectAccess(202))
	assert.True(t, g.HasProjectAccess(201))
	assert.False(t, g.CanListAllProjects())
	access := g.OrgAccess()
	assert.Equal(t, pb.Role_Viewer, access.Role)
	assert.Equal(t, pb.Role_None, access.ExplicitRole)

	// spec: 302 org Admin keeps Admin in 201 despite the project Viewer grant
	g = grantsOf(302)
	assert.Equal(t, pb.Role_Admin, g.HighestRole(201, []string{"Admin"}))
	assert.True(t, g.CanListAllProjects())

	// spec: 303 org Viewer reads every project
	g = grantsOf(303)
	assert.Equal(t, pb.Role_Viewer, g.HighestRole(202, []string{"Viewer"}))
	assert.Equal(t, pb.Role_None, g.HighestRole(202, []string{"User"}))
	assert.True(t, g.CanListAllProjects())

	// not a member
	g = grantsOf(999)
	assert.False(t, g.IsMember())
	assert.Empty(t, g.Roles(0))
	assert.Empty(t, g.Roles(201))
	role, source = g.ResolvedOrgRole()
	assert.Equal(t, pb.Role_None, role)
	assert.Equal(t, pb.RoleSource_Unknown, source)

	var nilGrants *authctx.Grants
	assert.False(t, nilGrants.IsMember())
	assert.Nil(t, nilGrants.Roles(0))
	assert.Nil(t, nilGrants.GrantedProjectIDs())
	assert.False(t, nilGrants.CanListAllProjects())
	assert.False(t, nilGrants.CanGrantOrgRole(pb.Role_Viewer))
	assert.False(t, nilGrants.CanGrantProjectRole(201, pb.Role_Viewer))
}

func Test_Grantable(t *testing.T) {
	t.Parallel()

	owner := grantsOf(304)
	admin := grantsOf(302)
	user := grantsOf(300)
	projectAdmin := grantsOf(301)
	billing := grantsOf(305)

	// org-wide grants
	assert.True(t, owner.CanGrantOrgRole(pb.Role_Owner))
	assert.True(t, owner.CanGrantOrgRole(pb.Role_Viewer))
	assert.True(t, admin.CanGrantOrgRole(pb.Role_Admin))
	assert.False(t, admin.CanGrantOrgRole(pb.Role_Owner), "only Owner grants Owner")
	assert.False(t, user.CanGrantOrgRole(pb.Role_Viewer))
	assert.False(t, billing.CanGrantOrgRole(pb.Role_Viewer))
	assert.False(t, projectAdmin.CanGrantOrgRole(pb.Role_Viewer), "project Admin cannot grant org-wide")
	assert.False(t, owner.CanGrantOrgRole(pb.Role_None))
	assert.False(t, owner.CanGrantOrgRole(pb.Role_APIKey))

	// project grants
	assert.True(t, owner.CanGrantProjectRole(202, pb.Role_Admin))
	assert.True(t, admin.CanGrantProjectRole(202, pb.Role_User))
	assert.True(t, projectAdmin.CanGrantProjectRole(201, pb.Role_Security))
	assert.False(t, projectAdmin.CanGrantProjectRole(202, pb.Role_Viewer), "no grant in project 202")
	assert.True(t, user.CanGrantProjectRole(201, pb.Role_Viewer), "300 is Admin in 201")
	assert.False(t, user.CanGrantProjectRole(202, pb.Role_Viewer))
	assert.False(t, owner.CanGrantProjectRole(201, pb.Role_Owner), "Owner is not a project role")
	assert.False(t, owner.CanGrantProjectRole(201, pb.Role_Billing), "Billing is not a project role")
}
