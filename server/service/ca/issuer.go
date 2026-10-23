package ca

import (
	"context"

	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/server/service/internal/caapi"
	"github.com/effective-security/xdb"
	"google.golang.org/grpc/codes"
)

// GetIssuer returns an issuer of the org by ID, by label resolved in the
// project then in the org, or by IKID. An issuer found by ID or IKID must
// be of a project the caller can read, or org-wide (Scope.RowAccess).
func (s *Service) GetIssuer(ctx context.Context, req *pb.GetIssuerRequest) (*pb.Issuer, error) {
	if req == nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "missing request")
	}
	orgID, err := s.scope.Org(ctx, req.OrgID)
	if err != nil {
		return nil, err
	}
	var row *model.Issuer
	switch {
	case req.ID != "":
		row, err = s.scope.Issuer(ctx, orgID, req.ID, pb.CA_GetIssuer_FullMethodName)
	case req.Label != "":
		var projectID xdb.ID
		projectID, err = s.scope.Project(ctx, orgID, req.ProjectID)
		if err != nil {
			return nil, err
		}
		row, err = s.scope.IssuerByLabel(ctx, orgID, projectID, req.Label)
	case req.IKID != "":
		row, err = s.db.GetIssuerBySKID(ctx, req.IKID)
		if err != nil {
			if xdb.IsNotFoundError(err) {
				return nil, httperror.NewGrpcFromCtx(ctx, codes.NotFound, "issuer not found")
			}
			return nil, httperror.WrapWithCtx(ctx, err, "unable to find issuer")
		}
		row, err = s.scope.VisibleIssuer(ctx, orgID, row, pb.CA_GetIssuer_FullMethodName)
	default:
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "issuer ID, label or IKID is required")
	}
	if err != nil {
		return nil, err
	}
	return caapi.IssuerPb(ctx, row)
}

// ListIssuers returns the issuers of the org, newest first; a project
// limits the result to its own issuers. Without a project, a member with
// project grants only lists the org-wide issuers and those of its projects.
func (s *Service) ListIssuers(ctx context.Context, req *pb.ListIssuersRequest) (*pb.IssuersResponse, error) {
	if req == nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "missing request")
	}
	orgID, err := s.scope.Org(ctx, req.OrgID)
	if err != nil {
		return nil, err
	}
	projectID, err := s.scope.Project(ctx, orgID, req.ProjectID)
	if err != nil {
		return nil, err
	}
	cursor, err := listCursor(ctx, req.Cursor)
	if err != nil {
		return nil, err
	}
	q := &query.ListIssuersRequest{
		OrgID:     orgID.UInt64(),
		ProjectID: projectID.UInt64(),
		Status:    req.Status,
		Type:      req.Type,
		Limit:     listLimit(req.Limit),
		Offset:    req.Offset,
		Cursor:    cursor,
	}
	if projectID.IsZero() {
		q.ProjectIDs, err = s.scope.ListProjects(ctx, orgID)
		if err != nil {
			return nil, err
		}
	}
	res, err := s.db.ListIssuers(ctx, q)
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "failed to list issuers")
	}
	list, err := res.Pb()
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "invalid issuer config")
	}
	return list, nil
}
