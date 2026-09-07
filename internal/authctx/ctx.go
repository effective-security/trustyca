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

// TrustyCtx provides trustyca context
type TrustyCtx interface {
	UserID() xdb.ID
	Name() string
	Email() string
	// AppRole returns current user role in App service from the token context (trusty-admin, user, guest)
	AppRole() string
	// Target of the request, e.g. HTTP path or gRPC method
	Target() string
	UserAgent() string
	AuthMethod() identity.AuthMethod
	// Memberships returns current user project memberships from the token context
	Memberships() map[string]pb.Role_Enum
}

type trustycactx struct {
	userID     xdb.ID
	userName   string
	userEmail  string
	orgs       map[string]pb.Role_Enum
	role       string
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
	AppRole    string              `json:"role"`
	Target     string              `json:"target"`
	UserAgent  string              `json:"ua"`
	AuthMethod identity.AuthMethod `json:"auth_method"`
}

// UserID returns current user ID from the token context
func (s *trustycactx) UserID() xdb.ID {
	return s.userID
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
func (c *trustycactx) Target() string {
	return c.target
}

// UserAgent returns request's user agent
func (c *trustycactx) UserAgent() string {
	return c.userAgent
}

// Memberships returns current user project memberships from the token context
func (s *trustycactx) Memberships() map[string]pb.Role_Enum {
	return s.orgs
}

// AppRole returns current user role in App service from the token context
func (s *trustycactx) AppRole() string {
	return s.role
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
	rctx := &trustycactx{
		role:       role,
		authMethod: idn.AuthMethod(),
		target:     idnCtx.Target(),
		userAgent:  idnCtx.UserAgent(),
	}

	if !strings.EqualFold(role, "guest") {
		_ = rctx.userID.Set(idn.Subject())
		claims := idn.Claims()

		var jwtclaims jwt.Claims
		err := claims.To(&jwtclaims)
		if err == nil {
			rctx.userName = jwtclaims.Name
			rctx.userEmail = jwtclaims.Email
		}

		if orgs := claims.StringsMap("orgs"); orgs != nil {
			rctx.orgs = map[string]pb.Role_Enum{}
			for id, role := range orgs {
				rctx.orgs[id] = RoleEnumValue[role]
			}
			logger.ContextKV(ctx, xlog.DEBUG, "status", "authenticated")
		}
	}

	ctx = context.WithValue(ctx, keyContext, rctx)
	// Add state to the context
	beState := &trustycaCtxState{
		UserID:     rctx.userID,
		Name:       rctx.userName,
		Email:      rctx.userEmail,
		AppRole:    rctx.role,
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
				// if !strings.HasPrefix(ss.TrustyRole, "trustyca") {
				// 	logger.ContextKV(ctx, xlog.WARNING,
				// 		"reason", "trusty_context_not_valid",
				// 		"email", ss.Email,
				// 		"role", TrustyRole,
				// 	)
				// 	// TODO check access to Backend
				// 	// return nil, errors.New("trusty context is not valid")
				// }
				rctx := &trustycactx{
					role:       ss.AppRole,
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

// FindCallerRole returns the role of the current user for the given org ID
func FindCallerRole(ctx TrustyCtx, orgID string) pb.Role_Enum {
	orgs := ctx.Memberships()
	if len(orgs) == 0 {
		return pb.Role_None
	}
	role, ok := orgs[orgID]
	if !ok {
		return pb.Role_None
	}
	return role
}
