package orgs

import (
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/mocks/mocktrustycadb"
	"github.com/effective-security/xdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestService_Projects(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := mocktrustycadb.NewMockOrgsDb(ctrl)
	db.EXPECT().TryCreateEvent(gomock.Any()).AnyTimes()
	az := newFakeAuthorizer(orgGrant(42, pb.Role_Admin))
	svc := Service{db: db, authorizer: az}

	ctx := testCtx("42", "1")
	noOrg := testCtx("42", "")

	// register
	_, err := svc.RegisterProject(noOrg, &pb.RegisterProjectRequest{Name: "Payments"})
	assert.EqualError(t, err, "unauthorized: org not selected")

	_, err = svc.RegisterProject(ctx, &pb.RegisterProjectRequest{Name: "  "})
	assert.EqualError(t, err, "bad_request: name is required")

	db.EXPECT().GetOrg(gomock.Any(), uint64(1)).Return(&model.Org{ID: xdb.NewID(1), Status: pb.ItemStatus_Inactive}, nil)
	_, err = svc.RegisterProject(ctx, &pb.RegisterProjectRequest{Name: "Payments"})
	assert.EqualError(t, err, "unexpected: org is deleted")

	db.EXPECT().GetOrg(gomock.Any(), uint64(1)).Return(testOrg, nil)
	db.EXPECT().RegisterProject(gomock.Any(), gomock.Any()).DoAndReturn(func(_ any, p *model.Project) (*model.Project, error) {
		assert.Equal(t, uint64(1), p.OrgID.UInt64())
		assert.Equal(t, "payments", p.Alias)
		assert.Equal(t, "Payments", p.Name)
		return testProject, nil
	})
	project, err := svc.RegisterProject(ctx, &pb.RegisterProjectRequest{Name: " Payments ", Alias: "payments"})
	require.NoError(t, err)
	assert.Equal(t, "201", project.ID)
	assert.Equal(t, "1", project.OrgID)

	db.EXPECT().GetOrg(gomock.Any(), uint64(1)).Return(testOrg, nil)
	db.EXPECT().RegisterProject(gomock.Any(), gomock.Any()).Return(nil, errors.New("duplicate"))
	_, err = svc.RegisterProject(ctx, &pb.RegisterProjectRequest{Name: "Payments"})
	assert.EqualError(t, err, "unexpected: failed to register project")

	// update
	_, err = svc.UpdateProject(ctx, &pb.UpdateProjectRequest{ProjectID: "bad"})
	assert.EqualError(t, err, "bad_request: invalid project ID")
	_, err = svc.UpdateProject(ctx, &pb.UpdateProjectRequest{ProjectID: "301", Name: "x"})
	assert.EqualError(t, err, "not_found: project not found", "project of another org")
	_, err = svc.UpdateProject(ctx, &pb.UpdateProjectRequest{ProjectID: "203", Name: "x"})
	assert.EqualError(t, err, "not_found: project not found", "inactive project")

	db.EXPECT().UpdateProject(gomock.Any(), &query.UpdateProjectRequest{ID: 201, Name: "Renamed", Description: "d"}).Return(&model.Project{
		ID: xdb.NewID(201), OrgID: xdb.NewID(1), Alias: "payments", Name: "Renamed", Status: pb.ItemStatus_Active,
	}, nil)
	project, err = svc.UpdateProject(ctx, &pb.UpdateProjectRequest{ProjectID: "201", Name: " Renamed ", Description: "d"})
	require.NoError(t, err)
	assert.Equal(t, "Renamed", project.Name)
	assert.Contains(t, az.invalidated, "project:201")

	// get by ID and by alias
	project, err = svc.GetProject(ctx, &pb.GetProjectRequest{ProjectID: "201"})
	require.NoError(t, err)
	assert.Equal(t, "payments", project.Alias)

	_, err = svc.GetProject(ctx, &pb.GetProjectRequest{})
	assert.EqualError(t, err, "bad_request: project ID or alias is required")

	db.EXPECT().FindProject(gomock.Any(), uint64(1), "payments").Return(testProject, nil)
	project, err = svc.GetProject(ctx, &pb.GetProjectRequest{Alias: "payments"})
	require.NoError(t, err)
	assert.Equal(t, "201", project.ID)

	db.EXPECT().FindProject(gomock.Any(), uint64(1), "nope").Return(nil, errors.New("record not found"))
	_, err = svc.GetProject(ctx, &pb.GetProjectRequest{Alias: "nope"})
	assert.EqualError(t, err, "not_found: unable to find project")

	// by alias resolves the project and authorizes project:read for it:
	// a project-only member of 201 cannot read project 203 by alias
	projectOnly := Service{db: db, authorizer: newFakeAuthorizer(projectGrant(7, 201, pb.Role_Admin))}
	db.EXPECT().FindProject(gomock.Any(), uint64(1), "payments").Return(testProject, nil)
	project, err = projectOnly.GetProject(testCtx("7", "1"), &pb.GetProjectRequest{Alias: "payments"})
	require.NoError(t, err)
	assert.Equal(t, "201", project.ID)
	other := &model.Project{ID: xdb.NewID(202), OrgID: xdb.NewID(1), Alias: "other", Name: "Other", Status: pb.ItemStatus_Active}
	db.EXPECT().FindProject(gomock.Any(), uint64(1), "other").Return(other, nil)
	_, err = projectOnly.GetProject(testCtx("7", "1"), &pb.GetProjectRequest{Alias: "other"})
	assert.EqualError(t, err, "not_found: project not found")

	// list: org Admin lists all projects
	db.EXPECT().ListProjects(gomock.Any(), &query.ListProjectsRequest{OrgID: 1, Limit: 100}).Return(&model.ProjectResult{
		Rows: model.ProjectSlice{testProject},
	}, nil)
	list, err := svc.ListProjects(ctx, &pb.ListProjectsRequest{})
	require.NoError(t, err)
	require.Len(t, list.Projects, 1)

	// list: a project-only member sees only granted projects
	db.EXPECT().ListProjects(gomock.Any(), &query.ListProjectsRequest{OrgID: 1, IDs: []uint64{201}, Limit: 100}).Return(&model.ProjectResult{
		Rows: model.ProjectSlice{testProject},
	}, nil)
	list, err = projectOnly.ListProjects(testCtx("7", "1"), &pb.ListProjectsRequest{})
	require.NoError(t, err)
	require.Len(t, list.Projects, 1)

	// list: a member without any grant in the org gets nothing without a DB call
	list, err = projectOnly.ListProjects(testCtx("8", "1"), &pb.ListProjectsRequest{})
	require.NoError(t, err)
	assert.Empty(t, list.Projects)

	db.EXPECT().ListProjects(gomock.Any(), gomock.Any()).Return(nil, errors.New("db failed"))
	_, err = svc.ListProjects(ctx, &pb.ListProjectsRequest{Limit: 5})
	assert.EqualError(t, err, "unexpected: failed to list projects")

	// delete deactivates
	db.EXPECT().UpdateProject(gomock.Any(), &query.UpdateProjectRequest{ID: 201, Status: pb.ItemStatus_Inactive}).Return(&model.Project{
		ID: xdb.NewID(201), OrgID: xdb.NewID(1), Alias: "payments", Name: "Payments", Status: pb.ItemStatus_Inactive,
	}, nil)
	project, err = svc.DeleteProject(ctx, &pb.DeleteProjectRequest{ProjectID: "201"})
	require.NoError(t, err)
	assert.Equal(t, pb.ItemStatus_Inactive, project.Status)

	_, err = svc.DeleteProject(ctx, &pb.DeleteProjectRequest{ProjectID: "301"})
	assert.EqualError(t, err, "not_found: project not found")
}
