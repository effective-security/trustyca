package ca

import (
	"github.com/effective-security/porto/gserver"
	"github.com/effective-security/trustyca/api/client"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/config"
	"github.com/effective-security/trustyca/server/service/shared"
	"github.com/effective-security/xlog"
	"google.golang.org/grpc"
)

// ServiceName provides the Service Name for this package
const ServiceName = "ca"

var logger = xlog.NewPackageLogger("github.com/effective-security/trustyca/server/service", ServiceName)

// Service defines the CA service (pb.CA) of the tenants: the users and the
// API keys of an org. It holds no issuer key and reads no CA table: every
// method copies the public request into its privpb counterpart with the org
// of the caller's token and forwards it to the backend service
// (server/service/backend, DESIGN.md section 2.1), in process when this
// process runs it, else over gRPC with the `ca` service client, with the
// context of the caller.
type Service struct {
	server  gserver.GServer
	backend *shared.BackendLocator
}

// Factory returns a factory of the service
func Factory(server gserver.GServer) any {
	if server == nil {
		logger.Panic("ca.Factory: invalid parameter")
	}

	return func(clients client.Factory) {
		svc := New(shared.NewBackendLocator(server.Discovery, clients, client.ClientNameCA, config.BackendServerName))
		svc.server = server
		server.AddService(svc)
	}
}

// New returns the service that forwards to the backend the locator finds;
// without a locator every method is Unavailable
func New(backend *shared.BackendLocator) *Service {
	return &Service{
		backend: backend,
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
	if s.backend != nil {
		if err := s.backend.Close(); err != nil {
			logger.KV(xlog.ERROR, "reason", "close_backend", "err", err.Error())
		}
	}
	logger.KV(xlog.INFO, "closed", ServiceName)
}

// RegisterGRPC registers gRPC handler
func (s *Service) RegisterGRPC(r *grpc.Server) {
	pb.RegisterCAServer(r, s)
}
