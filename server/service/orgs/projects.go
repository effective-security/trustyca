package orgs

import (
	"context"
	"fmt"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/authctx"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xlog"
	"google.golang.org/grpc/codes"
)

// defaultListLimit is used when a list request does not specify a limit
const defaultListLimit = 100

// parseOptionalID parses an optional ID; an empty value returns a zero ID
func parseOptionalID(ctx context.Context, val, what string) (xdb.ID, error) {
	if val == "" {
		return xdb.ID{}, nil
	}
	id, err := xdb.ParseID(val)
	if err != nil {
		return xdb.ID{}, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid %s", what)
	}
	return id, nil
}

// getActiveOrg returns the org, or an error if it does not exist or is deleted
func (s *Service) getActiveOrg(ctx context.Context, orgID xdb.ID) (*model.Org, error) {
	org, err := s.db.GetOrg(ctx, orgID.UInt64())
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "unable to find org")
	}
	if org.Status == pb.ItemStatus_Inactive {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.FailedPrecondition, "org is deleted")
	}
	return org, nil
}

// getProject returns the active project of the org, or nil when projectID
// is zero. A project of another org or an inactive project is reported as
// not found, so that project existence is not leaked across orgs.
func (s *Service) getProject(ctx context.Context, orgID, projectID xdb.ID) (*model.Project, error) {
	if projectID.UInt64() == 0 {
		return nil, nil
	}
	project, err := s.authorizer.Project(ctx, orgID, projectID)
	if err != nil {
		if errors.Is(err, authctx.ErrAccessDenied) {
			return nil, httperror.NewGrpcFromCtx(ctx, codes.NotFound, "project not found")
		}
		return nil, httperror.WrapWithCtx(ctx, err, "unable to find project")
	}
	return project, nil
}

// RegisterProject creates a project in the org selected in the token
func (s *Service) RegisterProject(ctx context.Context, req *pb.RegisterProjectRequest) (*pb.Project, error) {
	orgID, err := tokenOrg(ctx)
	if err != nil {
		return nil, err
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "name is required")
	}

	_, err = s.getActiveOrg(ctx, orgID)
	if err != nil {
		return nil, err
	}

	project, err := s.db.RegisterProject(ctx, &model.Project{
		OrgID:       orgID,
		Alias:       strings.TrimSpace(req.Alias),
		Name:        name,
		Description: xdb.NULLString(req.Description),
		Status:      pb.ItemStatus_Active,
	})
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "failed to register project")
	}

	logger.ContextKV(ctx, xlog.NOTICE,
		"org", orgID.UnderscoreString(),
		"project", project.ID.UnderscoreString(),
		"alias", project.Alias)
	s.event(ctx, orgID, project.ID, project.ID, pb.EventType_ProjectCreated,
		fmt.Sprintf("project %s created", project.Name))

	return project.Pb(), nil
}

// UpdateProject updates a project
func (s *Service) UpdateProject(ctx context.Context, req *pb.UpdateProjectRequest) (*pb.Project, error) {
	orgID, err := tokenOrg(ctx)
	if err != nil {
		return nil, err
	}
	projectID, err := xdb.ParseID(req.ProjectID)
	if err != nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid project ID")
	}
	_, err = s.getProject(ctx, orgID, projectID)
	if err != nil {
		return nil, err
	}

	project, err := s.db.UpdateProject(ctx, &query.UpdateProjectRequest{
		ID:          projectID.UInt64(),
		Name:        strings.TrimSpace(req.Name),
		Description: req.Description,
	})
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "failed to update project")
	}
	s.authorizer.InvalidateProject(ctx, projectID.String())
	s.event(ctx, orgID, project.ID, project.ID, pb.EventType_ProjectUpdated,
		fmt.Sprintf("project %s updated", project.Name))
	return project.Pb(), nil
}

// GetProject returns a project by ID or alias
func (s *Service) GetProject(ctx context.Context, req *pb.GetProjectRequest) (*pb.Project, error) {
	orgID, err := tokenOrg(ctx)
	if err != nil {
		return nil, err
	}

	if req.ProjectID != "" {
		projectID, err := xdb.ParseID(req.ProjectID)
		if err != nil {
			return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid project ID")
		}
		// the interceptor already authorized project:read for ProjectID
		project, err := s.getProject(ctx, orgID, projectID)
		if err != nil {
			return nil, err
		}
		return project.Pb(), nil
	}
	if req.Alias == "" {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "project ID or alias is required")
	}

	project, err := s.db.FindProject(ctx, orgID.UInt64(), req.Alias)
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "unable to find project")
	}
	// the request carried no ProjectID, so authorize the resolved project:
	// any role at the project may read it
	tctx := authctx.FromContext(ctx)
	if tctx.IsAPIKey() {
		if kp := tctx.ProjectID(); kp.UInt64() != 0 && kp.UInt64() != project.ID.UInt64() {
			return nil, httperror.NewGrpcFromCtx(ctx, codes.NotFound, "project not found")
		}
	} else if _, _, err = s.authorizer.CheckRole(ctx, orgID, project.ID, tctx.UserID(), pb.Role_Viewer.String()); err != nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.NotFound, "project not found")
	}
	return project.Pb(), nil
}

// ListProjects returns the projects of the org selected in the token that
// the caller can access: all projects with an org-wide role, otherwise only
// the projects with an explicit grant
func (s *Service) ListProjects(ctx context.Context, req *pb.ListProjectsRequest) (*pb.ProjectsResponse, error) {
	orgID, err := tokenOrg(ctx)
	if err != nil {
		return nil, err
	}
	tctx := authctx.FromContext(ctx)
	var grants *authctx.Grants
	if tctx.IsAPIKey() {
		// an API key lists the org projects, or its own project only
		grants = &authctx.Grants{OrgID: orgID, OrgRole: pb.Role_APIKey, ProjectRoles: map[uint64]pb.Role_Enum{}}
		if kp := tctx.ProjectID(); kp.UInt64() != 0 {
			grants.OrgRole = pb.Role_None
			grants.ProjectRoles[kp.UInt64()] = pb.Role_APIKey
		}
	} else {
		grants, err = s.authorizer.Grants(ctx, orgID, tctx.UserID())
		if err != nil {
			return nil, httperror.WrapWithCtx(ctx, err, "failed to resolve access")
		}
	}

	limit := req.Limit
	if limit == 0 {
		limit = defaultListLimit
	}
	q := &query.ListProjectsRequest{
		OrgID:  orgID.UInt64(),
		Status: req.Status,
		Limit:  limit,
		Offset: req.Offset,
	}
	if !grants.CanListAllProjects() {
		ids := grants.GrantedProjectIDs()
		if len(ids) == 0 {
			return &pb.ProjectsResponse{}, nil
		}
		q.IDs = ids
	}
	res, err := s.db.ListProjects(ctx, q)
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "failed to list projects")
	}
	return res.Pb(), nil
}

// DeleteProject deactivates a project.
// Memberships, invites and records owned by the project are kept.
func (s *Service) DeleteProject(ctx context.Context, req *pb.DeleteProjectRequest) (*pb.Project, error) {
	orgID, err := tokenOrg(ctx)
	if err != nil {
		return nil, err
	}
	projectID, err := xdb.ParseID(req.ProjectID)
	if err != nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid project ID")
	}
	_, err = s.getProject(ctx, orgID, projectID)
	if err != nil {
		return nil, err
	}

	project, err := s.db.UpdateProject(ctx, &query.UpdateProjectRequest{
		ID:     projectID.UInt64(),
		Status: pb.ItemStatus_Inactive,
	})
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "failed to update project status")
	}
	s.authorizer.InvalidateProject(ctx, projectID.String())

	logger.ContextKV(ctx, xlog.NOTICE,
		"org", orgID.UnderscoreString(),
		"project", projectID.UnderscoreString(),
		"status", project.Status.String())
	s.event(ctx, orgID, project.ID, project.ID, pb.EventType_ProjectDeleted,
		fmt.Sprintf("project %s deleted", project.Name))

	return project.Pb(), nil
}
