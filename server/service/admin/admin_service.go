package admin

import (
	"github.com/effective-security/porto/gserver"
	"github.com/effective-security/porto/restserver"
	"github.com/effective-security/trustyca/internal/db"
	"github.com/effective-security/trustyca/privpb"
	"github.com/effective-security/trustyca/privpb/httppb"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/dataprotection"
	"google.golang.org/grpc"
)

// ServiceName provides the Service Name for this package
const ServiceName = "admin"

var logger = xlog.NewPackageLogger("github.com/effective-security/trustyca/server/service", ServiceName)

// Service defines the Admin service
type Service struct {
	server         gserver.GServer
	db             db.OrgsDb
	dataprotection dataprotection.Provider
}

// Factory returns a factory of the service
func Factory(server gserver.GServer) any {
	if server == nil {
		logger.Panic("admin.Factory: invalid parameter")
	}

	return func(orgsDb db.OrgsDb, dataprotection dataprotection.Provider) {
		svc := &Service{
			server:         server,
			db:             orgsDb,
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

// RegisterGRPC registers gRPC handler
func (s *Service) RegisterGRPC(r *grpc.Server) {
	privpb.RegisterAdminServer(r, s)
}

func (s *Service) AdminHTTPHandler() restserver.Handle {
	return httppb.GetAdminHTTPHandler(s, nil)
}

// RegisterRoute adds the Admin API endpoints to the URL router
func (s *Service) RegisterRoute(r restserver.Router) {
	r.POST("/privpb.Admin/:action", s.AdminHTTPHandler())
}
