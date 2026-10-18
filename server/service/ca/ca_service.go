package ca

import (
	"github.com/effective-security/porto/gserver"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/authctx"
	core "github.com/effective-security/trustyca/internal/ca"
	"github.com/effective-security/trustyca/internal/config"
	"github.com/effective-security/trustyca/internal/db"
	"github.com/effective-security/xlog"
	"google.golang.org/grpc"
)

// ServiceName provides the Service Name for this package
const ServiceName = "ca"

var logger = xlog.NewPackageLogger("github.com/effective-security/trustyca/server/service", ServiceName)

// Service defines the CA service: issuers, trust anchors, profiles,
// certificates and revocation status of the org of the request. Issuers
// and profiles are resolved from the DB through the issuer registry of
// internal/ca, which caches the built issuers per row.
type Service struct {
	server     gserver.GServer
	authorizer authctx.Authorizer
	cfg        *config.Configuration
	db         db.CaDb
	orgs       db.OrgsDb
	registry   *core.Registry
}

// Factory returns a factory of the service
func Factory(server gserver.GServer) any {
	if server == nil {
		logger.Panic("ca.Factory: invalid parameter")
	}

	return func(cfg *config.Configuration,
		caDb db.CaDb,
		orgsDb db.OrgsDb,
		authorizer authctx.Authorizer,
		registry *core.Registry) {
		svc := &Service{
			server:     server,
			authorizer: authorizer,
			cfg:        cfg,
			db:         caDb,
			orgs:       orgsDb,
			registry:   registry,
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
	pb.RegisterCAServer(r, s)
}
