package cis

import (
	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/gserver"
	"github.com/effective-security/porto/restserver"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/api/pb/httppb"
	"github.com/effective-security/trustyca/internal/db"
	"github.com/effective-security/xlog"
	"google.golang.org/grpc"
)

// ServiceName provides the Service Name for this package
const ServiceName = "cis"

var logger = xlog.NewPackageLogger("github.com/effective-security/trustyca/server/service", ServiceName)

// Service defines the Certificate Information Service (pb.CIS): the
// read-only view of the CA tables (trust anchors, issuer chains,
// certificates, revocation status and CRLs) served over gRPC and the JSON
// API to the authenticated callers of the wfe listener. The binary AIA,
// CRL and OCSP routes the issued certificates point at are the aia service
// on its own plain HTTP listener; the CIS holds no issuer keys and calls no
// other service.
type Service struct {
	server gserver.GServer
	db     db.CaReadonlyDb
}

// Factory returns a factory of the service
func Factory(server gserver.GServer) any {
	if server == nil {
		logger.Panic("cis.Factory: invalid parameter")
	}

	return func(caDb db.CaReadonlyDb) error {
		svc, err := New(caDb)
		if err != nil {
			return err
		}
		svc.server = server
		server.AddService(svc)
		return nil
	}
}

// New returns the service over the CA tables
func New(caDb db.CaReadonlyDb) (*Service, error) {
	if caDb == nil {
		return nil, errors.New("cis.New: invalid parameter")
	}
	return &Service{
		db: caDb,
	}, nil
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

// CisHTTPHandler returns the handler of the JSON API. There is no
// per-method access check: the methods declare no roles and the views
// carry no tenancy, so the listener decides who reaches them (the wfe
// admits authenticated callers under authz.allow_any_role)
func (s *Service) CisHTTPHandler() restserver.Handle {
	return httppb.GetCISHTTPHandler(s, nil)
}

// RegisterRoute adds the JSON API to the overall URL router
func (s *Service) RegisterRoute(r restserver.Router) {
	r.POST(pb.PathForCIS, s.CisHTTPHandler())
}

// RegisterGRPC registers gRPC handler
func (s *Service) RegisterGRPC(r *grpc.Server) {
	pb.RegisterCISServer(r, s)
}
