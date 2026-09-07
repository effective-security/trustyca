package orgs

import (
	"context"

	"github.com/effective-security/porto/gserver"
	"github.com/effective-security/porto/restserver"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/api/pb/httppb"
	"github.com/effective-security/trustyca/internal/authctx"
	"github.com/effective-security/trustyca/internal/config"
	"github.com/effective-security/trustyca/internal/db"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/dataprotection"
	"google.golang.org/grpc"
)

// ServiceName provides the Service Name for this package
const ServiceName = "orgs"

var logger = xlog.NewPackageLogger("github.com/effective-security/trustyca/server/service", ServiceName)

// Service defines the Orgs service
type Service struct {
	server         gserver.GServer
	roleChecker    authctx.RoleChecker
	cfg            *config.Configuration
	db             db.OrgsDb
	dataprotection dataprotection.Provider
}

// Factory returns a factory of the service
func Factory(server gserver.GServer) any {
	if server == nil {
		logger.Panic("trustyca.Factory: invalid parameter")
	}

	return func(cfg *config.Configuration,
		trustycaDb db.OrgsDb,
		dataprotection dataprotection.Provider,
		roleChecker authctx.RoleChecker) {
		svc := &Service{
			server:         server,
			roleChecker:    roleChecker,
			cfg:            cfg,
			db:             trustycaDb,
			dataprotection: dataprotection,
		}

		server.AddService(svc)
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

// Close the subservices and its resources
func (s *Service) Close() {
	logger.KV(xlog.INFO, "closed", ServiceName)
}

func (s *Service) checkRoleForAction(ctx context.Context, req any, action string) error {
	return authctx.CheckAccess(ctx, s.roleChecker, req, action)
}

func (s *Service) OrgsHTTPHandler() restserver.Handle {
	return httppb.GetOrgsHTTPHandler(s, s.checkRoleForAction)
}

// RegisterRoute adds the Status API endpoints to the overall URL router
func (s *Service) RegisterRoute(r restserver.Router) {
	r.POST("/pb.Orgs/:action", s.OrgsHTTPHandler())
}

// RegisterGRPC registers gRPC handler
func (s *Service) RegisterGRPC(r *grpc.Server) {
	pb.RegisterOrgsServer(r, s)
}
