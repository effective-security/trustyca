package admin

import (
	"context"

	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/privpb"
	"google.golang.org/grpc/codes"
)

// ListCertificates lists the certificates of the org the request names, of
// the platform, or of every org and the platform, newest first, for
// support staff
func (s *Service) ListCertificates(ctx context.Context, req *privpb.ListCertificatesRequest) (*pb.CertificatesResponse, error) {
	if req == nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "missing request")
	}
	scope, err := parseListScope(ctx, req.OrgID, req.ProjectID, req.Platform)
	if err != nil {
		return nil, err
	}
	cursor, err := listCursor(ctx, req.Cursor)
	if err != nil {
		return nil, err
	}
	expiringBefore, err := parseTime(ctx, req.ExpiringBefore, "ExpiringBefore")
	if err != nil {
		return nil, err
	}
	res, err := s.ca.ListCertificates(ctx, &query.ListCertificatesRequest{
		OrgID:          scope.orgID,
		Platform:       scope.platform,
		AllOrgs:        scope.allOrgs,
		ProjectID:      scope.projectID,
		IKID:           req.IKID,
		Profile:        req.Profile,
		Status:         req.Status,
		ExpiringBefore: expiringBefore,
		Limit:          req.Limit,
		Offset:         req.Offset,
		Cursor:         cursor,
	})
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "failed to list certificates")
	}
	return res.Pb(), nil
}
