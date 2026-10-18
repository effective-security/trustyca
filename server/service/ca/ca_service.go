package ca

import (
	"github.com/effective-security/porto/gserver"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/authctx"
	"github.com/effective-security/trustyca/internal/config"
	"github.com/effective-security/trustyca/internal/db"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/authority"
	"github.com/effective-security/xpki/dataprotection"
	"google.golang.org/grpc"
)

// ServiceName provides the Service Name for this package
const ServiceName = "ca"

var logger = xlog.NewPackageLogger("github.com/effective-security/trustyca/server/service", ServiceName)

// Service defines the CA service.
// The issuers and profiles come from the bootstrap authority until
// internal/ca resolves them from the DB (PLAN.md phase 2, items 3 to 5).
type Service struct {
	server         gserver.GServer
	authorizer     authctx.Authorizer
	cfg            *config.Configuration
	db             db.CaDb
	orgs           db.OrgsReadonlyDb
	dataprotection dataprotection.Provider
	ca             *authority.Authority
}

// Factory returns a factory of the service
func Factory(server gserver.GServer) any {
	if server == nil {
		logger.Panic("ca.Factory: invalid parameter")
	}

	return func(cfg *config.Configuration,
		caDb db.CaDb,
		orgsDb db.OrgsReadonlyDb,
		dataprotection dataprotection.Provider,
		authorizer authctx.Authorizer,
		ca *authority.Authority) {
		svc := &Service{
			server:         server,
			authorizer:     authorizer,
			cfg:            cfg,
			db:             caDb,
			orgs:           orgsDb,
			dataprotection: dataprotection,
			ca:             ca,
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
