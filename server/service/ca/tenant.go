package ca

import (
	"context"
	"net/http"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/authctx"
	"github.com/effective-security/xdb"
	"google.golang.org/grpc/codes"
)

// tenantOrg returns the org of a tenant request. A user or API key token
// carries the selected org, and an explicit OrgID in the request must match
// it. A trusted service caller (RA, CIS, jobs over mTLS) has no org in its
// token and names the org explicitly; the org must exist and be active.
func (s *Service) tenantOrg(ctx context.Context, reqOrgID string) (xdb.ID, error) {
	tctx := authctx.FromContext(ctx)
	orgID := tctx.OrgID()
	if !orgID.IsZero() {
		if reqOrgID != "" && reqOrgID != orgID.String() {
			return xdb.ID{}, httperror.NewGrpcFromCtx(ctx, codes.PermissionDenied, "org mismatch")
		}
		return orgID, nil
	}
	if !strings.HasPrefix(tctx.AppRole(), authctx.ServiceRolePrefix) {
		return xdb.ID{}, httperror.NewGrpcFromCtx(ctx, codes.PermissionDenied, "org not selected")
	}
	if reqOrgID == "" {
		return xdb.ID{}, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "org ID is required")
	}
	orgID, err := xdb.ParseID(reqOrgID)
	if err != nil {
		return xdb.ID{}, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid org ID")
	}
	org, err := s.orgs.GetOrg(ctx, orgID.UInt64())
	if err != nil {
		if xdb.IsNotFoundError(err) {
			return xdb.ID{}, httperror.NewGrpcFromCtx(ctx, codes.NotFound, "org not found")
		}
		return xdb.ID{}, httperror.WrapWithCtx(ctx, err, "unable to find org")
	}
	if org.Status != pb.ItemStatus_Active {
		return xdb.ID{}, preconditionFailed(ctx, "org is deleted")
	}
	return orgID, nil
}

// tenantProject returns the project of a tenant request, or a zero ID for
// the org scope. A project of another org or an inactive project is reported
// as not found, so that project existence is not leaked across orgs.
func (s *Service) tenantProject(ctx context.Context, orgID xdb.ID, reqProjectID string) (xdb.ID, error) {
	if reqProjectID == "" {
		return xdb.ID{}, nil
	}
	projectID, err := xdb.ParseID(reqProjectID)
	if err != nil {
		return xdb.ID{}, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid project ID")
	}
	_, err = s.authorizer.Project(ctx, orgID, projectID)
	if err != nil {
		if errors.Is(err, authctx.ErrAccessDenied) {
			return xdb.ID{}, httperror.NewGrpcFromCtx(ctx, codes.NotFound, "project not found")
		}
		return xdb.ID{}, httperror.WrapWithCtx(ctx, err, "unable to find project")
	}
	return projectID, nil
}

// preconditionFailed returns the error of a request that the current state
// of the org refuses, and that the caller can make pass by changing that
// state: HTTP 409 Conflict with code "conflict", and gRPC FailedPrecondition.
// The pinned porto maps FailedPrecondition to HTTP 500, so it is built from
// the HTTP status and returned unwrapped.
func preconditionFailed(ctx context.Context, msgFormat string, vals ...any) *httperror.Error {
	e := httperror.NewFromCtx(ctx, http.StatusConflict, httperror.CodeConflict, msgFormat, vals...)
	e.RPCStatus = codes.FailedPrecondition
	return e
}
