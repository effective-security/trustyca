package pgsql

import (
	"context"
	"fmt"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/internal/db/schema"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xpki/certutil"
)

// RegisterProject creates a project in an org
func (p *Provider) RegisterProject(ctx context.Context, m *model.Project) (*model.Project, error) {
	project := *m
	if project.ID.UInt64() == 0 {
		project.ID = p.NextID()
	}
	if project.Alias == "" {
		project.Alias = model.ProjectAliasPrefix + certutil.RandomString(28)
	}

	err := xdb.Validate(&project)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	q, name := query.RegisterProject()
	defer DbMeasureQuerySince(name, time.Now())

	res, err := xdb.QueryRow[model.Project](ctx, p,
		q,
		project.ID,
		project.OrgID,
		project.Alias,
		project.Name,
		project.Description,
	)
	if err != nil {
		p.CheckErrIDConflict(ctx, err, project.ID.UInt64())
		return nil, err
	}
	return res, nil
}

// UpdateProject updates a project's name, description or status
func (p *Provider) UpdateProject(ctx context.Context, req *query.UpdateProjectRequest) (*model.Project, error) {
	if req.Name == "" && req.Description == "" && req.Status == 0 {
		return nil, errors.New("no changes to update")
	}
	if len(req.Name) > 64 {
		return nil, errors.Errorf("invalid name: %q", req.Name)
	}

	qp := req.QueryParams()
	q, qname := query.UpdateProject(qp)
	defer DbMeasureQuerySince(qname, time.Now())

	res, err := xdb.QueryRow[model.Project](ctx, p, q, qp.Args()...)
	if err != nil {
		return nil, xdb.CheckNotFoundError(err, schema.ProjectTableInfo.Name, req.ID)
	}
	return res, nil
}

// GetProject returns Project by ID
func (p *Provider) GetProject(ctx context.Context, id uint64) (*model.Project, error) {
	q, name := query.GetRowByID(&schema.ProjectTableInfo, id)
	defer DbMeasureQuerySince(name, time.Now())

	res, err := xdb.QueryRow[model.Project](ctx, p, q, id)
	if err != nil {
		return nil, xdb.CheckNotFoundError(err, schema.ProjectTableInfo.Name, id)
	}
	return res, nil
}

// FindProject returns Project by org and alias
func (p *Provider) FindProject(ctx context.Context, orgID uint64, alias string) (*model.Project, error) {
	q, name := query.GetProjectByAlias()
	defer DbMeasureQuerySince(name, time.Now())

	res, err := xdb.QueryRow[model.Project](ctx, p, q, orgID, alias)
	if err != nil {
		return nil, xdb.CheckNotFoundError(err, schema.ProjectTableInfo.Name, fmt.Sprintf("%d/%s", orgID, alias))
	}
	return res, nil
}

// ListProjects lists projects of an org
func (p *Provider) ListProjects(ctx context.Context, req *query.ListProjectsRequest) (*model.ProjectResult, error) {
	qp := req.QueryParams()
	q, name := query.ListProjects(qp)
	defer DbMeasureQuerySince(name, time.Now())

	var rs model.ProjectResult
	err := xdb.ExecuteQueryWithPagination(ctx, p, &rs, q, qp)
	if err != nil {
		return nil, err
	}
	return &rs, nil
}
