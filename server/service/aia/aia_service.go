package aia

import (
	"cmp"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/gserver"
	"github.com/effective-security/porto/restserver"
	"github.com/effective-security/trustyca/api/client"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/config"
	"github.com/effective-security/trustyca/internal/db"
	"github.com/effective-security/trustyca/privpb"
	"github.com/effective-security/trustyca/server/service/shared"
	"github.com/effective-security/xlog"
)

// ServiceName provides the Service Name for this package
const ServiceName = "aia"

// defaultOcspCacheSize is the number of OCSP responses kept in memory when
// the configuration sets none
const defaultOcspCacheSize = 10000

var logger = xlog.NewPackageLogger("github.com/effective-security/trustyca/server/service", ServiceName)

// Service defines the Authority Information Access service: the binary
// routes the issued certificates point at, served to any caller over the
// plain HTTP listener of the service, as RFC 5280 requires of the AIA and
// CRL Distribution Point URLs: the issuer certificate (AIA caIssuers), the
// current CRL (CDP) and the OCSP responder. The service is REST only, reads
// the CA tables and holds no issuer keys: OCSP requests are forwarded to
// the backend service (privpb.Backend) and the signed responses are cached
// until their NextUpdate.
type Service struct {
	cfg   *config.Configuration
	db    db.CaReadonlyDb
	cache *ocspCache

	// the backend the OCSP requests are forwarded to: the backend service
	// of the process, else a client of the backend listener with the `aia`
	// service client, created on the first request
	backend *shared.BackendLocator
}

// Factory returns a factory of the service
func Factory(server gserver.GServer) any {
	if server == nil {
		logger.Panic("aia.Factory: invalid parameter")
	}

	return func(cfg *config.Configuration,
		caDb db.CaReadonlyDb,
		clients client.Factory) error {
		backend := shared.NewBackendLocator(server.Discovery, clients, client.ClientNameAIA, config.BackendServerName)
		svc, err := New(cfg, caDb, backend)
		if err != nil {
			return err
		}
		server.AddService(svc)
		return nil
	}
}

// New returns the service over the CA tables. The backend locator returns
// the backend the OCSP requests are forwarded to; without one every OCSP
// request answers tryLater.
func New(cfg *config.Configuration, caDb db.CaReadonlyDb, backend *shared.BackendLocator) (*Service, error) {
	if cfg == nil || caDb == nil {
		return nil, errors.New("aia.New: invalid parameter")
	}
	cache, err := newOcspCache(cmp.Or(cfg.AIA.OcspCacheSize, defaultOcspCacheSize))
	if err != nil {
		return nil, err
	}
	return &Service{
		cfg:     cfg,
		db:      caDb,
		cache:   cache,
		backend: backend,
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
	if s.backend != nil {
		if err := s.backend.Close(); err != nil {
			logger.KV(xlog.ERROR, "reason", "close_backend", "err", err.Error())
		}
	}
	logger.KV(xlog.INFO, "closed", ServiceName)
}

// RegisterRoute adds the binary AIA, CDP and OCSP routes to the overall
// URL router; the service has no gRPC API
func (s *Service) RegisterRoute(r restserver.Router) {
	r.GET(pb.PathForCert, s.IssuerHandler())
	r.GET(pb.PathForCRL, s.CRLHandler())
	r.GET(pb.PathForGetOCSP, s.GetOcspHandler())

	r.POST(pb.PathForOCSPByIssuerID, s.OCSPHandler())

	r.GET(pb.PathForGetOCSPByBody, s.GetOcspHandler())
	r.POST(pb.PathForOCSP, s.OCSPHandler())
}

// signer returns the backend the OCSP requests are forwarded to; a backend
// that is not reachable fails the call, and the next request tries again
func (s *Service) signer() (privpb.BackendServer, error) {
	if s.backend == nil {
		return nil, errors.New("backend is not configured")
	}
	return s.backend.Backend()
}
