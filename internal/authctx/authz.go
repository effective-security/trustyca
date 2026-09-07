package authctx

import (
	"context"
	"strings"

	"github.com/effective-security/porto/restserver/telemetry"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/porto/xhttp/identity"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/x/values"
	"github.com/effective-security/xlog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

// OrgRequester specifies if request contains OrgID
type OrgRequester interface {
	GetOrgID() string
}

// NewAuthUnaryInterceptor returns grpc.UnaryServerInterceptor that
// checks access to the method
func NewAuthUnaryInterceptor(checkRole RoleChecker, skipLogPaths []telemetry.LoggerSkipPath) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		ctx = NewTrustyCtx(ctx, identity.FromContext(ctx))
		err := CheckAccess(ctx, checkRole, req, info.FullMethod, skipLogPaths...)
		if err != nil {
			return nil, err
		}

		return handler(ctx, req)
	}
}

// CheckAccess performs action check
func CheckAccess(ctx context.Context, checkRole RoleChecker, req any, action string, skipLogPaths ...telemetry.LoggerSkipPath) error {
	trustycactx := FromContext(ctx)
	trustycaRole := trustycactx.AppRole()

	isStatusService := strings.HasPrefix(action, "/pb.Status")
	isOrgsService := strings.HasPrefix(action, "/pb.Orgs")
	isPrivpbService := strings.HasPrefix(action, "/privpb.")
	if !isOrgsService && !isPrivpbService {
		// Only Orgs and Admin are required Org AuthZ
		// TODO:
		return nil
	}

	if isPrivpbService || isStatusService {
		if strings.HasPrefix(trustycaRole, "trustyca-viewer") {
			// allow read-only access for trustyca-viewer roles, and SupportTenant which checks org membership
			if action == "/privpb.Admin/SupportTenant" ||
				strings.HasPrefix(action, "/privpb.Admin/Get") ||
				strings.HasPrefix(action, "/privpb.Admin/List") {
				return nil
			}
		} else if strings.HasPrefix(trustycaRole, "trustyca-admin") {
			// allow any action for trustyca roles: admin, job, worker
			return nil
		} else if strings.HasPrefix(trustycaRole, "trustyca-") {
			// allow any action for trustyca roles: admin, job, worker
			// TODO: remove this check when all endpoints will be secured
			if !telemetry.ShouldSkip(skipLogPaths, action, "*") {
				l := values.Select(isStatusService, xlog.DEBUG, xlog.TRACE)
				logger.ContextKV(ctx, l, "reason", "trustyca", "action", action)
			}
			return nil
		}

		// for other roles, deny access
		if isPrivpbService {
			logger.ContextKV(ctx, xlog.WARNING, "reason", "privpb", "action", action, "role", trustycaRole)
			return httperror.NewGrpcFromCtx(ctx, codes.PermissionDenied, "access denied")
		}
	}

	var err error
	rule := pb.GetMethodInfo(action)
	if rule != nil && len(rule.AllowedRoles) > 0 {
		if trustycaRole == "" || trustycaRole == "guest" {
			// Trusty endpoints require authenticated call
			return httperror.NewGrpcFromCtx(ctx, codes.Unauthenticated, "access denied")
		}

		if byOrg, ok := req.(OrgRequester); ok {
			orgID := byOrg.GetOrgID()
			if memberships := trustycactx.Memberships(); memberships != nil {
				role := memberships[orgID]
				if role == pb.Role_None || !CanAssumeRole(role, rule.AllowedRoles) {
					err = httperror.NewGrpcFromCtx(ctx, codes.PermissionDenied, "insufficient role: %s, action: %s", role.String(), action)
				}
			} else {
				_, err = checkRole.CheckRole(ctx, orgID, trustycactx.UserID(), rule.AllowedRoles...)
			}
		}
	}
	if err != nil {
		logger.ContextKV(ctx, xlog.NOTICE,
			"action", action,
			"reason", "denied",
			"role", trustycaRole,
		)

		return err
	}
	logger.ContextKV(ctx, xlog.NOTICE,
		"action", action,
		"reason", "allowed",
		"role", trustycaRole,
	)
	return nil
}
