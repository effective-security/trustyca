package cis

import (
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
const ServiceName = "cis"

var logger = xlog.NewPackageLogger("github.com/effective-security/trustyca/server/service", ServiceName)

// Service defines the CA service
type Service struct {
	server         gserver.GServer
	authorizer     authctx.Authorizer
	cfg            *config.Configuration
	db             db.OrgsDb // TODO: use db.CaDb
	dataprotection dataprotection.Provider
}

// Factory returns a factory of the service
func Factory(server gserver.GServer) any {
	if server == nil {
		logger.Panic("cis.Factory: invalid parameter")
	}

	return func(cfg *config.Configuration,
		trustycaDb db.OrgsDb,
		dataprotection dataprotection.Provider,
		authorizer authctx.Authorizer) {
		svc := &Service{
			server:         server,
			authorizer:     authorizer,
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

func (s *Service) CisHTTPHandler() restserver.Handle {
	// no need to check role for CIS service as there is no access by OrgID or TeamID
	return httppb.GetCISHTTPHandler(s, nil)
}

// RegisterRoute adds the Status API endpoints to the overall URL router
func (s *Service) RegisterRoute(r restserver.Router) {
	r.GET(pb.PathForCert, s.IssuerHandler())
	r.GET(pb.PathForCRL, s.CRLHandler())
	r.GET(pb.PathForGetOCSP, s.OCSPHandler())
	r.POST(pb.PathForOCSPByIssuerID, s.OCSPHandler())
	r.POST(pb.PathForOCSP, s.OCSPHandler())
}

// RegisterGRPC registers gRPC handler
func (s *Service) RegisterGRPC(r *grpc.Server) {
	pb.RegisterCISServer(r, s)
}
