package admin

import (
	"context"

	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/privpb"
)

func (s *Service) ListOrgs(ctx context.Context, req *privpb.ListOrgsRequest) (*pb.OrgsResponse, error) {
	orgs, err := s.db.ListOrgs(ctx, &query.ListOrgsRequest{
		Status: req.Status,
		Limit:  req.Limit,
		Offset: req.Offset,
	})
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "failed to list orgs")
	}
	return orgs.Pb(), nil
}
