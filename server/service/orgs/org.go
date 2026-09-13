package orgs

import (
	"context"
	"fmt"

	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/authctx"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/xdb"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/emptypb"
)

// tokenOrg returns the org selected in the token
func tokenOrg(ctx context.Context) (xdb.ID, error) {
	orgID := authctx.FromContext(ctx).OrgID()
	if orgID.UInt64() == 0 {
		return xdb.ID{}, httperror.NewGrpcFromCtx(ctx, codes.PermissionDenied, "org not selected")
	}
	return orgID, nil
}

// event records an audit event asynchronously
func (s *Service) event(ctx context.Context, orgID, projectID, refID xdb.ID, typ pb.EventType_Enum, title string) {
	tctx := authctx.FromContext(ctx)
	s.db.TryCreateEvent(&model.Event{
		OrgID:       orgID,
		ProjectID:   projectID,
		Type:        typ,
		Title:       title,
		ReferenceID: refID,
		Email:       xdb.NULLString(tctx.Email()),
		Source:      xdb.NULLString(tctx.Target()),
	})
}

// RegisterOrg registers a new org; the caller becomes its Owner
func (s *Service) RegisterOrg(ctx context.Context, req *pb.RegisterOrgRequest) (*pb.Org, error) {
	trustyCtx := authctx.FromContext(ctx)
	userID := trustyCtx.UserID()
	if userID.UInt64() == 0 {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.Unauthenticated, "user is required")
	}
	org, err := s.db.RegisterOrg(ctx, &model.Org{
		Name:        req.Name,
		Description: xdb.NULLString(req.Description),
		Status:      pb.ItemStatus_Active,
	}, userID.UInt64())
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "failed to register org")
	}
	s.authorizer.InvalidateUser(ctx, userID.String())
	s.event(ctx, org.ID, xdb.ID{}, org.ID, pb.EventType_OrgCreated,
		fmt.Sprintf("org %s created by %s", org.Name, trustyCtx.Email()))
	return org.Pb(), nil
}

// GetOrg returns the org selected in the token
func (s *Service) GetOrg(ctx context.Context, _ *emptypb.Empty) (*pb.Org, error) {
	orgID, err := tokenOrg(ctx)
	if err != nil {
		return nil, err
	}
	org, err := s.db.GetOrg(ctx, orgID.UInt64())
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "failed to get org")
	}
	return org.Pb(), nil
}

// UpdateOrg updates the org selected in the token
func (s *Service) UpdateOrg(ctx context.Context, req *pb.UpdateOrgRequest) (*pb.Org, error) {
	orgID, err := tokenOrg(ctx)
	if err != nil {
		return nil, err
	}
	org, err := s.db.UpdateOrg(ctx, &query.UpdateOrgRequest{ID: orgID.UInt64(), Name: req.Name, Description: req.Description})
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "failed to update org")
	}
	s.event(ctx, org.ID, xdb.ID{}, org.ID, pb.EventType_OrgUpdated, fmt.Sprintf("org %s updated", org.Name))
	return org.Pb(), nil
}

// DeleteOrg deactivates the org selected in the token
func (s *Service) DeleteOrg(ctx context.Context, _ *emptypb.Empty) (*pb.Org, error) {
	orgID, err := tokenOrg(ctx)
	if err != nil {
		return nil, err
	}
	userID := authctx.FromContext(ctx).UserID()
	org, err := s.db.UpdateOrg(ctx, &query.UpdateOrgRequest{ID: orgID.UInt64(), Status: pb.ItemStatus_Inactive})
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "failed to update org status")
	}
	s.authorizer.InvalidateUser(ctx, userID.String())
	s.event(ctx, org.ID, xdb.ID{}, org.ID, pb.EventType_OrgDeleted, fmt.Sprintf("org %s deleted", org.Name))
	return org.Pb(), nil
}
