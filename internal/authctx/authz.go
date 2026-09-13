package authctx

import (
	"context"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/restserver/telemetry"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/porto/xhttp/identity"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/x/values"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xlog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

// OrgRequester specifies if request contains an explicit OrgID.
// Tenant requests take the org from the token; an explicit OrgID is only
// accepted from trusted service identities, or when it matches the token.
type OrgRequester interface {
	GetOrgID() string
}

// ProjectRequester specifies if request contains ProjectID.
// An empty ProjectID means the request is Org scope.
type ProjectRequester interface {
	GetProjectID() string
}

// ServiceRolePrefix marks trusted service identities (mTLS peers), which pass
// tenant scope explicitly and are not subject to membership checks
// TODO: add a config option for the service role prefix
const ServiceRolePrefix = "trustyca-"

// identityServicePrefix marks the identity and session API, which operates
// before an org is selected and is gated by the server authz config
const identityServicePrefix = "/pb.Auth/"

// NewAuthUnaryInterceptor returns grpc.UnaryServerInterceptor that
// checks access to the method
func NewAuthUnaryInterceptor(authorizer Authorizer, skipLogPaths []telemetry.LoggerSkipPath) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		ctx = NewTrustyCtx(ctx, identity.FromContext(ctx))
		err := CheckAccess(ctx, authorizer, req, info.FullMethod, skipLogPaths...)
		if err != nil {
			return nil, err
		}

		return handler(ctx, req)
	}
}

// CheckAccess authorizes the action for the caller.
//
// Two method options drive the check:
//
//   - (es.api.allowed_roles) lists the minimum roles allowed to call the
//     method at org scope, or at project scope when the request carries
//     ProjectID. A caller passes when one of its roles at that scope can
//     assume an allowed role (CanAssumeRoles). Methods without allowed roles
//     require an authenticated caller only.
//   - (es.api.scopes) lists the scopes an API key, or a token with a scope
//     claim, must hold in addition. API keys are allowed only when the
//     allowed roles include APIKey; they are checked against the token
//     scopes, never against memberships.
//
// Admin (privpb) and status services are restricted to trustyca-* service
// roles; identity and session methods (pb.Auth) are gated by the server
// authz config only.
func CheckAccess(ctx context.Context, authorizer Authorizer, req any, action string, skipLogPaths ...telemetry.LoggerSkipPath) error {
	tctx := FromContext(ctx)
	appRole := tctx.AppRole()

	isStatusService := strings.HasPrefix(action, "/pb.Status")
	isPrivpbService := strings.HasPrefix(action, "/privpb.")

	if isPrivpbService || isStatusService {
		if strings.HasPrefix(appRole, "trustyca-viewer") {
			// allow read-only access for trustyca-viewer roles
			if action == "/privpb.Admin/SupportTenant" ||
				strings.HasPrefix(action, "/privpb.Admin/Get") ||
				strings.HasPrefix(action, "/privpb.Admin/List") {
				return nil
			}
		} else if strings.HasPrefix(appRole, "trustyca-admin") {
			return nil
		} else if strings.HasPrefix(appRole, ServiceRolePrefix) {
			// allow any action for trustyca roles: job, worker, peer
			if !telemetry.ShouldSkip(skipLogPaths, action, "*") {
				l := values.Select(isStatusService, xlog.DEBUG, xlog.TRACE)
				logger.ContextKV(ctx, l, "reason", "trustyca", "action", action)
			}
			return nil
		}

		if isPrivpbService {
			logger.ContextKV(ctx, xlog.WARNING, "reason", "privpb", "action", action, "role", appRole)
			return httperror.NewGrpcFromCtx(ctx, codes.PermissionDenied, "access denied")
		}
		return nil
	}

	if strings.HasPrefix(action, identityServicePrefix) {
		return nil
	}

	rule := pb.GetMethodInfo(action)
	if rule == nil || len(rule.AllowedRoles) == 0 {
		// authenticated-only or public method; the server authz config
		// decides who may reach it
		return nil
	}

	if appRole == "" || strings.EqualFold(appRole, "guest") {
		return httperror.NewGrpcFromCtx(ctx, codes.Unauthenticated, "access denied")
	}

	if strings.HasPrefix(appRole, ServiceRolePrefix) {
		// trusted service identity (RA, CIS, jobs): tenant scope is passed
		// explicitly and was authorized by the caller
		logger.ContextKV(ctx, xlog.DEBUG, "reason", "service_role", "action", action, "role", appRole)
		return nil
	}

	orgID := tctx.OrgID()
	if orgID.UInt64() == 0 {
		return httperror.NewGrpcFromCtx(ctx, codes.PermissionDenied, "org not selected, action: %s", action)
	}
	if byOrg, ok := req.(OrgRequester); ok {
		if reqOrg := byOrg.GetOrgID(); reqOrg != "" && reqOrg != orgID.String() {
			logger.ContextKV(ctx, xlog.NOTICE, "action", action, "reason", "org_mismatch", "org", reqOrg)
			return httperror.NewGrpcFromCtx(ctx, codes.PermissionDenied, "org mismatch, action: %s", action)
		}
	}

	var projectID xdb.ID
	if byProject, ok := req.(ProjectRequester); ok {
		if pid := byProject.GetProjectID(); pid != "" {
			var err error
			projectID, err = xdb.ParseID(pid)
			if err != nil {
				return httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid project ID")
			}
		}
	}

	if tctx.IsAPIKey() {
		return checkAPIKeyAccess(ctx, authorizer, tctx, rule, action, orgID, projectID)
	}

	role, _, err := authorizer.CheckRole(ctx, orgID, projectID, tctx.UserID(), rule.AllowedRoles...)
	if err != nil {
		logger.ContextKV(ctx, xlog.NOTICE,
			"action", action,
			"reason", "denied",
			"role", tctx.OrgRole().String(),
			"project", projectID.UnderscoreString(),
			"err", err.Error(),
		)
		if errors.Is(err, ErrInsufficientRole) || errors.Is(err, ErrAccessDenied) || errors.Is(err, ErrOrgNotSelected) {
			return httperror.NewGrpcFromCtx(ctx, codes.PermissionDenied, "%s, action: %s", err.Error(), action)
		}
		return httperror.NewGrpcFromCtx(ctx, codes.PermissionDenied, "access denied, action: %s", action).WithCause(err)
	}

	// a scoped user token (a token that carries a scope claim) is further
	// limited to the scopes it holds
	if scopes := tctx.Scopes(); len(scopes) > 0 && !HasScopes(scopes, ParseScopes(rule.Scopes)) {
		logger.ContextKV(ctx, xlog.NOTICE, "action", action, "reason", "insufficient_scope", "role", role.String())
		return httperror.NewGrpcFromCtx(ctx, codes.PermissionDenied, "insufficient scope, action: %s", action)
	}

	logger.ContextKV(ctx, xlog.NOTICE,
		"action", action,
		"reason", "allowed",
		"role", role.String(),
		"project", projectID.UnderscoreString(),
	)
	return nil
}

// checkAPIKeyAccess authorizes an API key token: the method must allow the
// APIKey role, the request must stay within the key's project when the key
// is project scoped, the project must be an active project of the org, and
// the key scopes must cover the method scopes.
func checkAPIKeyAccess(ctx context.Context, authorizer Authorizer, tctx TrustyCtx, rule *pb.MethodInfo, action string, orgID, projectID xdb.ID) error {
	if !AllowsRole(rule.AllowedRoles, pb.Role_APIKey) {
		logger.ContextKV(ctx, xlog.NOTICE, "action", action, "reason", "apikey_not_allowed")
		return httperror.NewGrpcFromCtx(ctx, codes.PermissionDenied, "API key not allowed, action: %s", action)
	}
	if keyProject := tctx.ProjectID(); keyProject.UInt64() != 0 {
		// a project scoped key acts in its project only
		if projectID.UInt64() == 0 {
			projectID = keyProject
		} else if projectID.UInt64() != keyProject.UInt64() {
			logger.ContextKV(ctx, xlog.NOTICE, "action", action, "reason", "project_mismatch", "project", projectID.UnderscoreString())
			return httperror.NewGrpcFromCtx(ctx, codes.PermissionDenied, "project mismatch, action: %s", action)
		}
	}
	if projectID.UInt64() != 0 {
		if _, err := authorizer.Project(ctx, orgID, projectID); err != nil {
			logger.ContextKV(ctx, xlog.NOTICE, "action", action, "reason", "denied", "project", projectID.UnderscoreString(), "err", err.Error())
			return httperror.NewGrpcFromCtx(ctx, codes.PermissionDenied, "%s, action: %s", ErrAccessDenied.Error(), action)
		}
	}
	if !HasScopes(tctx.Scopes(), ParseScopes(rule.Scopes)) {
		logger.ContextKV(ctx, xlog.NOTICE, "action", action, "reason", "insufficient_scope", "scopes", rule.Scopes)
		return httperror.NewGrpcFromCtx(ctx, codes.PermissionDenied, "insufficient scope, action: %s", action)
	}
	logger.ContextKV(ctx, xlog.NOTICE,
		"action", action,
		"reason", "allowed",
		"role", pb.Role_APIKey.String(),
		"project", projectID.UnderscoreString(),
	)
	return nil
}
