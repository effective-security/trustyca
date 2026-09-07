package orgs

import (
	"context"

	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/authctx"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/xdb"
	"google.golang.org/grpc/codes"
)

func (s *Service) RegisterOrg(ctx context.Context, req *pb.RegisterOrgRequest) (*pb.Org, error) {
	trustyCtx := authctx.FromContext(ctx)
	userID := trustyCtx.UserID()
	org, err := s.db.RegisterOrg(ctx, &model.Org{
		Name:        req.Name,
		Description: xdb.NULLString(req.Description),
		Status:      pb.ItemStatus_Active,
	}, userID.UInt64())
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "failed to register org")
	}
	s.roleChecker.InvalidateCache(ctx, userID.String())
	return org.Pb(), nil
}

func (s *Service) GetOrg(ctx context.Context, req *pb.GetOrgRequest) (*pb.Org, error) {
	id, err := xdb.ParseID(req.OrgID)
	if err != nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid org ID")
	}
	org, err := s.db.GetOrg(ctx, id.UInt64())
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "failed to get org")
	}
	return org.Pb(), nil
}

func (s *Service) UpdateOrg(ctx context.Context, req *pb.UpdateOrgRequest) (*pb.Org, error) {
	id, err := xdb.ParseID(req.OrgID)
	if err != nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid org ID")
	}
	org, err := s.db.UpdateOrg(ctx, &query.UpdateOrgRequest{ID: id.UInt64(), Name: req.Name, Description: req.Description})
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "failed to update org")
	}
	return org.Pb(), nil
}

func (s *Service) DeleteOrg(ctx context.Context, req *pb.DeleteOrgRequest) (*pb.Org, error) {
	trustyCtx := authctx.FromContext(ctx)
	userID := trustyCtx.UserID()
	id, err := xdb.ParseID(req.OrgID)
	if err != nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid org ID")
	}
	org, err := s.db.UpdateOrg(ctx, &query.UpdateOrgRequest{ID: id.UInt64(), Status: pb.ItemStatus_Inactive})
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "failed to update org status")
	}
	s.roleChecker.InvalidateCache(ctx, userID.String())
	return org.Pb(), nil
}
