package authctx

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/effective-security/porto/xhttp/identity"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/jwt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/trustyca/internal", "authctx")

// Token claims set by the auth service
const (
	// ClaimOrg is the selected org ID (the tenant claim)
	ClaimOrg = "org"
	// ClaimOrgRole is the resolved org role: the explicit org-wide role,
	// or Viewer derived from project grants. It is informational; permissions
	// are always resolved from the grants in the DB.
	ClaimOrgRole = "org_role"
	// ClaimOrgRoleSource is "direct" for an explicit org-wide grant or
	// "project" for a derived Viewer classification
	ClaimOrgRoleSource = "org_role_source"
)

// TrustyCtx provides trustyca context
type TrustyCtx interface {
	// OrgID returns the org selected in the token, zero if none
	OrgID() xdb.ID
	UserID() xdb.ID
	Name() string
	Email() string
	// OrgRole returns the resolved role in the selected org from the token
	// (viewer, user, admin, owner), or APIKey for an API key token.
	// Permissions of users are resolved from grants; API keys are checked
	// against Scopes.
	OrgRole() pb.Role_Enum
	// ProjectID returns the project an API key is restricted to, zero if none
	ProjectID() xdb.ID
	// Scopes returns the scopes granted to an API key or a scoped token
	Scopes() []string
	// IsAPIKey returns true for an API key token
	IsAPIKey() bool
	// AppRole returns current user role in App service from the token context (trusty-admin, user, guest)
	AppRole() string
	// Target of the request, e.g. HTTP path or gRPC method
	Target() string
	UserAgent() string
	AuthMethod() identity.AuthMethod
}

type trustycactx struct {
	userID     xdb.ID
	userName   string
	userEmail  string
	orgID      xdb.ID
	orgRole    pb.Role_Enum
	projectID  xdb.ID
	scopes     []string
	appRole    string
	userAgent  string
	target     string
	authMethod identity.AuthMethod
}

// trustycaCtxState is the state of the Trusty context,
// used to serialize and deserialize the context to/from gRPC headers.
type trustycaCtxState struct {
	UserID     xdb.ID              `json:"user_id"`
	Name       string              `json:"user_name"`
	Email      string              `json:"user_email"`
	OrgID      xdb.ID              `json:"org_id"`
	OrgRole    pb.Role_Enum        `json:"org_role"`
	ProjectID  xdb.ID              `json:"project_id,omitempty"`
	Scopes     []string            `json:"scopes,omitempty"`
	AppRole    string              `json:"app_role"`
	Target     string              `json:"target"`
	UserAgent  string              `json:"ua"`
	AuthMethod identity.AuthMethod `json:"auth_method"`
}

// UserID returns current user ID from the token context
func (s *trustycactx) UserID() xdb.ID {
	return s.userID
}

// OrgID returns current Org ID from the token context
func (s *trustycactx) OrgID() xdb.ID {
	return s.orgID
}

// Name returns current user Name from the token context
func (s *trustycactx) Name() string {
	return s.userName
}

// Email returns current user Email from the token context
func (s *trustycactx) Email() string {
	return s.userEmail
}

// Target returns request's target
func (s *trustycactx) Target() string {
	return s.target
}

// UserAgent returns request's user agent
func (s *trustycactx) UserAgent() string {
	return s.userAgent
}

// OrgRole returns current user Org role from the token context
func (s *trustycactx) OrgRole() pb.Role_Enum {
	return s.orgRole
}

// ProjectID returns the project an API key is restricted to
func (s *trustycactx) ProjectID() xdb.ID {
	return s.projectID
}

// Scopes returns the scopes granted to an API key or a scoped token
func (s *trustycactx) Scopes() []string {
	return s.scopes
}

// IsAPIKey returns true for an API key token
func (s *trustycactx) IsAPIKey() bool {
	return s.orgRole == pb.Role_APIKey
}

// AppRole returns current user role in App service from the token context
func (s *trustycactx) AppRole() string {
	return s.appRole
}

// AuthMethod returns current authentication method
func (s *trustycactx) AuthMethod() identity.AuthMethod {
	return s.authMethod
}

// Handler returns http.Handler that extracts Trusty context
func Handler(delegate http.Handler) http.Handler {
	h := func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		v := ctx.Value(keyContext)
		if v == nil {
			r = r.WithContext(NewTrustyCtx(ctx, identity.FromContext(ctx)))
		}
		delegate.ServeHTTP(w, r)
	}
	return http.HandlerFunc(h)
}

type contextKey int

const (
	keyContext contextKey = iota
	keyIdentity
)

// FromContext extracts the TrustyCtx stored inside a go context.
// Returns empty context if no such value exists.
func FromContext(ctx context.Context) TrustyCtx {
	ret, _ := ctx.Value(keyContext).(*trustycactx)
	if ret == nil {
		ret = &trustycactx{}
	}
	return ret
}

// FromRequest returns the full context associcated with this http request.
func FromRequest(r *http.Request) TrustyCtx {
	return FromContext(r.Context())
}

// NewTrustyCtx returns new context.Context with TrustyCtx
func NewTrustyCtx(ctx context.Context, idnCtx identity.Context) context.Context {
	idn := idnCtx.Identity()
	role := idn.Role()
	orgID := idn.Tenant()
	rctx := &trustycactx{
		appRole:    role,
		authMethod: idn.AuthMethod(),
		target:     idnCtx.Target(),
		userAgent:  idnCtx.UserAgent(),
	}

	if !strings.EqualFold(role, "guest") {
		_ = rctx.userID.Set(idn.Subject())
		_ = rctx.orgID.Set(orgID)

		claims := idn.Claims()

		var jwtclaims jwt.Claims
		err := claims.To(&jwtclaims)
		if err == nil {
			rctx.userName = jwtclaims.Name
			rctx.userEmail = jwtclaims.Email
		}

		// the token carries the selected org and the resolved org role for
		// display; permissions are always resolved from the grants in the DB
		roleClaim := claims.String(ClaimOrgRole)
		rctx.orgRole = ParseRole(roleClaim)
		rctx.scopes = claims.Strings(ClaimScope)
		_ = rctx.projectID.Set(claims.String(ClaimProject))
		// NOTE: tenant, subject and app role already added by identity handler
		if rctx.orgRole != pb.Role_None {
			ctx = xlog.ContextWithKV(ctx, "org_role", roleClaim)
		}
		logger.ContextKV(ctx, xlog.DEBUG,
			"status", "authenticated",
			"org_id", orgID,
		)
	}

	ctx = context.WithValue(ctx, keyContext, rctx)
	// Add state to the context
	beState := &trustycaCtxState{
		UserID:     rctx.userID,
		OrgID:      rctx.orgID,
		Name:       rctx.userName,
		Email:      rctx.userEmail,
		AppRole:    rctx.appRole,
		OrgRole:    rctx.orgRole,
		ProjectID:  rctx.projectID,
		Scopes:     rctx.scopes,
		Target:     rctx.target,
		UserAgent:  rctx.userAgent,
		AuthMethod: rctx.authMethod,
	}
	js, err := json.Marshal(beState)
	if err != nil {
		return ctx
	}

	return metadata.AppendToOutgoingContext(ctx, trustycaContextGRPCHeaderName, string(js))
}

// trustycaContextGRPCHeaderName specifies default name for gRPC header
const trustycaContextGRPCHeaderName = "x-trustyca-context"

// NewAuthUnaryBackendInterceptor returns grpc.UnaryServerInterceptor that
// retrieves Trusty context from the incoming context
func NewAuthUnaryBackendInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		md, ok := metadata.FromIncomingContext(ctx)
		if ok && md != nil && len(md[trustycaContextGRPCHeaderName]) > 0 {
			var ss trustycaCtxState
			err := json.Unmarshal([]byte(md[trustycaContextGRPCHeaderName][0]), &ss)
			if err == nil {
				rctx := &trustycactx{
					appRole:    ss.AppRole,
					orgID:      ss.OrgID,
					orgRole:    ss.OrgRole,
					projectID:  ss.ProjectID,
					scopes:     ss.Scopes,
					userID:     ss.UserID,
					userName:   ss.Name,
					userEmail:  ss.Email,
					target:     ss.Target,
					userAgent:  ss.UserAgent,
					authMethod: ss.AuthMethod,
				}
				ctx = context.WithValue(ctx, keyContext, rctx)

				// Override the log context with Trusty context from WFE
				ctx = xlog.ContextWithKV(ctx,
					"user", ss.UserID.String(),
					"email", ss.Email,
					"role", ss.AppRole,
				)
			}
		}
		return handler(ctx, req)
	}
}
