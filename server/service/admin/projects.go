package admin

import (
	"context"

	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/privpb"
	"github.com/effective-security/xdb"
)

func (s *Service) ListProjects(ctx context.Context, req *privpb.ListProjectsRequest) (*pb.ProjectsResponse, error) {
	lreq := &query.ListProjectsRequest{
		Status: req.Status,
		Limit:  req.Limit,
		Offset: req.Offset,
	}
	if req.OrgID != "" {
		orgID, err := xdb.ParseID(req.OrgID)
		if err != nil {
			return nil, httperror.WrapWithCtx(ctx, err, "invalid org ID")
		}
		lreq.OrgID = orgID.UInt64()
	}

	projects, err := s.db.ListProjects(ctx, lreq)
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "failed to list projects")
	}
	return projects.Pb(), nil
}
