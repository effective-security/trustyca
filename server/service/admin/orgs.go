package admin

import (
	"context"

	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/privpb"
)

// ListOrgs lists the orgs by name, paged by cursor
func (s *Service) ListOrgs(ctx context.Context, req *privpb.ListOrgsRequest) (*pb.OrgsResponse, error) {
	cursor, err := query.ListCursor(ctx, req.Cursor, query.ParseNameCursor)
	if err != nil {
		return nil, err
	}
	qreq := &query.ListOrgsRequest{
		Status: req.Status,
		Limit:  query.Limit(req.Limit),
		Cursor: cursor,
	}
	orgs, err := s.db.ListOrgs(ctx, qreq)
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "failed to list orgs")
	}
	return orgs.Pb(), nil
}
