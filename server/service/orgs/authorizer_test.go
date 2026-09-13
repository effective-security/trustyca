package orgs

import (
	"context"

	"github.com/effective-security/porto/xhttp/identity"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/authctx"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/xdb"
)

// test fixtures: org 1 with projects 201 (active) and 203 (inactive);
// project 301 belongs to org 2
var (
	testOrg = &model.Org{
		ID:     xdb.NewID(1),
		Alias:  "cp_test",
		Name:   "Test Org",
		Status: pb.ItemStatus_Active,
	}
	testProject = &model.Project{
		ID:     xdb.NewID(201),
		OrgID:  xdb.NewID(1),
		Alias:  "payments",
		Name:   "Payments",
		Status: pb.ItemStatus_Active,
	}
	inactiveProject = &model.Project{
		ID:     xdb.NewID(203),
		OrgID:  xdb.NewID(1),
		Alias:  "old",
		Name:   "Old",
		Status: pb.ItemStatus_Inactive,
	}
	foreignProject = &model.Project{
		ID:     xdb.NewID(301),
		OrgID:  xdb.NewID(2),
		Alias:  "foreign",
		Name:   "Foreign",
		Status: pb.ItemStatus_Active,
	}
)

// fakeAuthorizer resolves grants from a fixed set of membership rows
type fakeAuthorizer struct {
	rows        model.MembershipInfoSlice
	projects    map[uint64]*model.Project
	invalidated []string
}

func newFakeAuthorizer(rows ...*model.MembershipInfo) *fakeAuthorizer {
	return &fakeAuthorizer{
		rows: rows,
		projects: map[uint64]*model.Project{
			testProject.ID.UInt64():     testProject,
			inactiveProject.ID.UInt64(): inactiveProject,
			foreignProject.ID.UInt64():  foreignProject,
		},
	}
}

func (f *fakeAuthorizer) Grants(_ context.Context, orgID, userID xdb.ID) (*authctx.Grants, error) {
	if orgID.UInt64() == 0 {
		return nil, authctx.ErrOrgNotSelected
	}
	return authctx.GrantsFromMemberships(f.rows, orgID, userID), nil
}

func (f *fakeAuthorizer) Project(_ context.Context, orgID, projectID xdb.ID) (*model.Project, error) {
	p, ok := f.projects[projectID.UInt64()]
	if !ok || p.OrgID.UInt64() != orgID.UInt64() || p.Status != pb.ItemStatus_Active {
		return nil, authctx.ErrAccessDenied
	}
	return p, nil
}

func (f *fakeAuthorizer) CheckRole(ctx context.Context, orgID, projectID, userID xdb.ID, allowedRoles ...string) (pb.Role_Enum, *authctx.Grants, error) {
	if projectID.UInt64() != 0 {
		if _, err := f.Project(ctx, orgID, projectID); err != nil {
			return pb.Role_None, nil, err
		}
	}
	g, err := f.Grants(ctx, orgID, userID)
	if err != nil {
		return pb.Role_None, nil, err
	}
	role := g.HighestRole(projectID.UInt64(), allowedRoles)
	if role == pb.Role_None {
		return pb.Role_None, g, authctx.ErrInsufficientRole
	}
	return role, g, nil
}

func (f *fakeAuthorizer) InvalidateUser(_ context.Context, userID string) {
	f.invalidated = append(f.invalidated, "user:"+userID)
}

func (f *fakeAuthorizer) InvalidateProject(_ context.Context, projectID string) {
	f.invalidated = append(f.invalidated, "project:"+projectID)
}

// testCtx returns a request context for the user with the org selected in
// the token. An empty orgID means no org is selected.
func testCtx(userID, orgID string) context.Context {
	claims := map[string]any{
		"sub":   userID,
		"email": "caller@example.com",
		"name":  "Caller",
	}
	if orgID != "" {
		claims[authctx.ClaimOrg] = orgID
	}
	uid := identity.NewIdentity("user", userID, orgID, claims, "tok", "Bearer", identity.MethodJWT)
	return authctx.NewTrustyCtx(context.Background(), identity.NewRequestContext(uid, "/test"))
}

func orgGrant(userID uint64, role pb.Role_Enum) *model.MembershipInfo {
	return &model.MembershipInfo{
		ID:      xdb.NewID(1000 + userID),
		OrgID:   testOrg.ID,
		OrgName: testOrg.Name,
		UserID:  xdb.NewID(userID),
		Email:   "user" + xdb.NewID(userID).String() + "@example.com",
		Role:    role,
	}
}

func projectGrant(userID uint64, projectID uint64, role pb.Role_Enum) *model.MembershipInfo {
	return &model.MembershipInfo{
		ID:           xdb.NewID(2000 + userID),
		OrgID:        testOrg.ID,
		OrgName:      testOrg.Name,
		ProjectID:    xdb.NewID(projectID),
		ProjectAlias: "payments",
		UserID:       xdb.NewID(userID),
		Email:        "user" + xdb.NewID(userID).String() + "@example.com",
		Role:         role,
	}
}
