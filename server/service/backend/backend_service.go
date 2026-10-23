package backend

import (
	"context"

	"github.com/effective-security/porto/gserver"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/trustyca/internal/authctx"
	core "github.com/effective-security/trustyca/internal/ca"
	"github.com/effective-security/trustyca/internal/db"
	"github.com/effective-security/trustyca/privpb"
	"github.com/effective-security/xlog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

// ServiceName provides the Service Name for this package
const ServiceName = "backend"

var logger = xlog.NewPackageLogger("github.com/effective-security/trustyca/server/service", ServiceName)

// Service defines the backend service (privpb.Backend), the CA of the
// service identities and the signing plane (DESIGN.md section 2.1): every
// method of pb.CA with the org of the request named explicitly. Issuers and
// profiles are resolved from the DB through the issuer registry of
// internal/ca, which caches the built issuers per row, and CRLs are signed
// by its publisher, which the crl_renewal task shares. A method runs as its
// caller: the CA service of the same process passes its caller's context,
// the backend listener builds the context of a caller the WFE forwards
// (authctx.NewAuthUnaryBackendInterceptor), and a service identity (the RA,
// the operator, the AIA) acts as itself.
type Service struct {
	server    gserver.GServer
	scope     *tenantScope
	db        db.CaDb
	orgs      db.OrgsDb
	registry  *core.Registry
	publisher *core.CrlPublisher
}

// Factory returns a factory of the service
func Factory(server gserver.GServer) any {
	if server == nil {
		logger.Panic("backend.Factory: invalid parameter")
	}

	return func(caDb db.CaDb,
		orgsDb db.OrgsDb,
		authorizer authctx.Authorizer,
		registry *core.Registry) {
		svc := New(caDb, orgsDb, authorizer, registry)
		svc.server = server
		server.AddService(svc)
	}
}

// New returns the backend service over the issuer registry; without a
// registry every method fails with Unavailable
func New(caDb db.CaDb, orgsDb db.OrgsDb, authorizer authctx.Authorizer, registry *core.Registry) *Service {
	svc := &Service{
		scope:    newTenantScope(authorizer, caDb, orgsDb),
		db:       caDb,
		orgs:     orgsDb,
		registry: registry,
	}
	if registry != nil {
		svc.publisher = core.NewCrlPublisher(caDb, registry)
	}
	return svc
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
	privpb.RegisterBackendServer(r, s)
}

// requireCA returns Unavailable when the backend has no issuer registry
func (s *Service) requireCA(ctx context.Context) error {
	if s.registry == nil {
		return httperror.NewGrpcFromCtx(ctx, codes.Unavailable, "CA is not configured")
	}
	return nil
}
