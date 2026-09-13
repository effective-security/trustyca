package auth

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/effective-security/porto/gserver"
	"github.com/effective-security/porto/pkg/cache"
	"github.com/effective-security/porto/restserver"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/api/pb/httppb"
	"github.com/effective-security/trustyca/internal/authctx"
	"github.com/effective-security/trustyca/internal/config"
	"github.com/effective-security/trustyca/internal/db"
	"github.com/effective-security/x/slices"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/dataprotection"
	"github.com/effective-security/xpki/jwt"
	"github.com/effective-security/xpki/jwt/oauth2client"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"google.golang.org/grpc"
)

// ServiceName provides the Service Name for this package
const ServiceName = "auth"

var logger = xlog.NewPackageLogger("github.com/effective-security/trustyca/server/service", ServiceName)

// Service defines the Auth service
type Service struct {
	// allow to change in unittest
	BaseURL   *url.URL
	JwtSigner jwt.Signer
	JwtParser jwt.Parser
	//Emailer   emailer.Provider

	//	clientFactory      backendclient.Factory
	authorizer     authctx.Authorizer
	server         gserver.GServer
	cfg            *config.Configuration
	dataprotection dataprotection.Provider
	db             db.OrgsDb
	cache          cache.Provider
	oauthProvider  *oauth2client.Provider

	allowedEmailsCache *expirable.LRU[string, *oauth2client.Client] // email -> *oauth2client.Client, or nil if not allowed
}

// Factory returns a factory of the service
func Factory(server gserver.GServer) any {
	if server == nil {
		logger.Panic("auth.Factory: invalid parameter")
	}

	return func(cfg *config.Configuration,
		oauthProvider *oauth2client.Provider,
		jwtParser jwt.Parser,
		jwtSigner jwt.Signer,
		dp dataprotection.Provider,
		trustycaDb db.OrgsDb,
		cache cache.Provider,
		authorizer authctx.Authorizer,
		//clientFactory backendclient.Factory,
		//emailer emailer.Provider,
	) error {
		svc := &Service{
			server:         server,
			cfg:            cfg,
			oauthProvider:  oauthProvider,
			JwtParser:      jwtParser,
			JwtSigner:      jwtSigner,
			dataprotection: dp,
			db:             trustycaDb,
			cache:          cache,
			authorizer:     authorizer,

			allowedEmailsCache: expirable.NewLRU[string, *oauth2client.Client](100, nil, 5*time.Minute),
		}

		server.AddService(svc)
		return nil
	}
}

// Name returns the service name
func (s *Service) Name() string {
	return ServiceName
}

// IsReady indicates that the service is ready to serve its end-points
func (s *Service) IsReady() bool {
	return true
}

// OnStarted is called when the server started and
// is ready to serve requests
func (s *Service) OnStarted() error {
	return nil
}

// Close the subservices and its resources
func (s *Service) Close() {
	logger.KV(xlog.INFO, "closed", ServiceName)
}

func (s *Service) checkRoleForAction(ctx context.Context, req any, action string) error {
	return authctx.CheckAccess(ctx, s.authorizer, req, action)
}

func (s *Service) AuthHTTPHandler() restserver.Handle {
	return httppb.GetAuthHTTPHandler(s, s.checkRoleForAction)
}

// RegisterRoute adds the Status API endpoints to the overall URL router
func (s *Service) RegisterRoute(r restserver.Router) {
	// add HTTP proxy
	r.POST(pb.PathForAuth, s.AuthHTTPHandler())

	r.GET(pb.PathForAuthProviders, s.AuthProvidersHandler())
	r.POST(pb.PathForAuthProviders, s.AuthProvidersHandler())
	// r.POST(pb.PathForAuthTenant, s.AuthTenantHandler())

	r.GET(pb.PathForAuthDone, s.AuthDoneHandler())
	r.POST(pb.PathForAuthDone, s.AuthDoneHandler())

	r.GET(pb.PathForAuthCallback, s.CallbackHandler())
	r.POST(pb.PathForAuthCallback, s.CallbackHandler())

	r.GET(pb.PathForAuthorize, s.AuthorizeHandler())
	// //r.POST(pb.PathForToken, s.TokenHandler())

	r.GET(pb.PathForAuthUserinfo, s.UserinfoHandler())
	r.GET(pb.PathForAuthUserToken, s.UserTokenHandler())

	r.GET(pb.PathForStatusCaller, s.callerStatus())

	r.GET(pb.Auth_RevokeToken_FullMethodName, s.RevokeTokenHandler())
	r.DELETE(pb.Auth_RevokeToken_FullMethodName, s.RevokeTokenHandler())

	// GET reads the API key headers; POST goes through the HTTP proxy
	r.GET(pb.Auth_AuthenticateAPIKey_FullMethodName, s.AuthenticateAPIKeyHandler())

	r.DELETE(pb.PathForRemoveCookie, s.RemoveCookieHandler())
}

// RegisterGRPC registers gRPC handler
func (s *Service) RegisterGRPC(r *grpc.Server) {
	pb.RegisterAuthServer(r, s)
}

// Protect returns encrypted value in base64url encoded format
func (s *Service) Protect(ctx context.Context, v any) (string, error) {
	return dataprotection.ProtectObject(ctx, s.dataprotection, v)
}

// Unprotect decrypts and unmarshals protected string to a struct
func (s *Service) Unprotect(ctx context.Context, protected string, v any) error {
	return dataprotection.UnprotectObject(ctx, s.dataprotection, protected, v)
}

// Db returns OrgsDb for unit tests
func (s *Service) Db() db.OrgsDb {
	return s.db
}

// OAuthConfig returns oauth2client.Config,
// to be used in tests
func (s *Service) AuthProvider(ctx context.Context, provider pb.IDP_Enum) (*oauth2client.Client, error) {
	p := s.oauthProvider.ClientForProvider(strings.ToLower(provider.String()))
	if p != nil {
		return p, nil
	}
	return nil, httperror.InvalidRequest("unsupported provider: %s", provider)
}

// AuthProviderForEmail checks if the email is allowed to login,
// and returns oauth2client.Client for the provider
func (s *Service) AuthProviderForEmail(ctx context.Context, email string) (cl *oauth2client.Client, err error) {
	if cl, found := s.allowedEmailsCache.Get(email); found {
		if cl == nil {
			return nil, errRestrictedUsers
		}
		return cl, nil
	}

	defer func() {
		s.allowedEmailsCache.Add(email, cl)
	}()

	err = s.isEmailAllowedLogin(ctx, email)
	if err != nil {
		return
	}
	cl = s.oauthProvider.ClientForEmail(email)
	if cl == nil {
		err = httperror.Forbidden("no provider for email: %s", email)
	}
	return
}

func (s *Service) isAllowedRedirect(redirect string) error {
	if len(s.cfg.Auth.AllowedRedirectDomains) == 0 {
		return nil
	}

	u, err := url.Parse(redirect)
	if err != nil {
		return httperror.Forbidden("invalid redirect_url")
	}

	if !slices.ContainsString(s.cfg.Auth.AllowedRedirectDomains, u.Hostname()) {
		return httperror.Forbidden("redirect_url not_allowed")
	}
	return nil
}

func (s *Service) isEmailAllowedLogin(ctx context.Context, email string) error {
	parts := strings.Split(email, "@")
	domain := parts[len(parts)-1]
	if slices.ContainsString(s.cfg.Auth.AllowedDomains, domain) {
		return nil
	}

	user, _ := s.db.GetUserByEmail(ctx, email)
	if user != nil {
		// user already exists
		return nil
	}
	invites, _ := s.db.GetUserInvites(ctx, email)
	if len(invites) > 0 {
		// user invited
		return nil
	}

	logger.ContextKV(ctx, xlog.DEBUG, "reason", "isEmailAllowedLogin", "email", email)
	return errRestrictedUsers
}
