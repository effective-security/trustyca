package orgs

import (
	"context"
	"net/http"

	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/authctx"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/internal/events"
	"github.com/effective-security/xdb"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/emptypb"
)

// tokenOrg returns the org selected in the token
func tokenOrg(ctx context.Context) (xdb.ID, error) {
	orgID := authctx.FromContext(ctx).OrgID()
	if orgID.UInt64() == 0 {
		return xdb.ID(0), httperror.NewGrpcFromCtx(ctx, codes.PermissionDenied, "org not selected")
	}
	return orgID, nil
}

// preconditionFailed returns the error of a request that the current state
// of the org or its resources refuses, and that the caller can make pass by
// changing that state: HTTP 409 Conflict with code "conflict", and gRPC
// FailedPrecondition. The pinned porto maps FailedPrecondition to HTTP 400
// bad_request, so the error carries both statuses instead of being built by
// NewGrpcFromCtx. Return it as is: httperror.Wrap with a message rebuilds it
// from its code, and gRPC gets AlreadyExists. A Go client of the gRPC API
// still converts it to a 400.
func preconditionFailed(ctx context.Context, msgFormat string, vals ...any) *httperror.Error {
	e := httperror.NewFromCtx(ctx, http.StatusConflict, httperror.CodeConflict, msgFormat, vals...)
	e.RPCStatus = codes.FailedPrecondition
	return e
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
	events.New(ctx, ServiceName, pb.EventType_OrgCreated, "Org created").
		Org(org.ID).
		Reference(org.ID).
		Description("org %q created", org.Name).
		Emit(s.db)
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
	events.New(ctx, ServiceName, pb.EventType_OrgUpdated, "Org updated").
		Org(org.ID).
		Reference(org.ID).
		Description("org %q updated", org.Name).
		Emit(s.db)
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
	events.New(ctx, ServiceName, pb.EventType_OrgDeleted, "Org deleted").
		Org(org.ID).
		Reference(org.ID).
		Description("org %q deleted", org.Name).
		Emit(s.db)
	return org.Pb(), nil
}
