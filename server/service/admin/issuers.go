package admin

import (
	"context"

	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/privpb"
	"github.com/effective-security/xlog"
	"google.golang.org/grpc/codes"
)

// ListIssuers lists the issuers of the org the request names, of the
// platform, or of every org and the platform, newest first, for support
// staff. Private key material is never part of the rows' API view.
func (s *Service) ListIssuers(ctx context.Context, req *privpb.ListAllIssuersRequest) (*pb.IssuersResponse, error) {
	if req == nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "missing request")
	}
	scope, err := parseListScope(ctx, req.OrgID, req.ProjectID, req.Platform)
	if err != nil {
		return nil, err
	}
	cursor, err := query.ListCursor(ctx, req.Cursor, query.ParseCursor)
	if err != nil {
		return nil, err
	}
	res, err := s.ca.ListIssuers(ctx, &query.ListIssuersRequest{
		OrgID:     scope.orgID,
		Platform:  scope.platform,
		AllOrgs:   scope.allOrgs,
		ProjectID: scope.projectID,
		Label:     req.Label,
		Status:    req.Status,
		Type:      req.Type,
		Limit:     req.Limit,
		Offset:    req.Offset,
		Cursor:    cursor,
	})
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "failed to list issuers")
	}
	list, err := res.Pb()
	if err != nil {
		// the stored settings of a row do not parse: the server's, not the
		// caller's
		logger.ContextKV(ctx, xlog.ERROR,
			"reason", "issuer_config",
			"err", err.Error())
		return nil, httperror.NewGrpcFromCtx(ctx, codes.Internal, "unable to read issuers")
	}
	return list, nil
}
