package status

import (
	"github.com/effective-security/porto/gserver"
	"github.com/effective-security/porto/restserver"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/xlog"
	"google.golang.org/grpc"
)

// ServiceName provides the Service Name for this package
const ServiceName = "status"

var logger = xlog.NewPackageLogger("github.com/effective-security/trustyca/server/service", "status")

// Service defines the Status service
type Service struct {
	server gserver.GServer
}

// Factory returns a factory of the service
func Factory(server gserver.GServer) any {
	if server == nil {
		logger.Panic("status.Factory: invalid parameter")
	}

	return func() {
		svc := &Service{
			server: server,
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

// RegisterRoute adds the Status API endpoints to the overall URL router
func (s *Service) RegisterRoute(r restserver.Router) {
	r.GET(pb.Status_Version_FullMethodName, s.version())
	r.GET(pb.PathForStatusVersion, s.version())
	r.GET(pb.Status_Server_FullMethodName, s.serverStatus())
	r.GET(pb.PathForStatusServer, s.serverStatus())
	r.GET("/healthz", s.nodeStatus())
	r.GET(pb.PathForStatusNode, s.nodeStatus())
	// "/" is served by the ui service
	// r.GET(pb.PathForMetrics, s.metricsHandler())
	// r.GET("/metrics", s.metricsHandler())
}

// RegisterGRPC registers gRPC handler
func (s *Service) RegisterGRPC(r *grpc.Server) {
	pb.RegisterStatusServer(r, s)
}
