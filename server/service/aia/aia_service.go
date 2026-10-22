package aia

import (
	"cmp"
	"io"
	"sync"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/gserver"
	"github.com/effective-security/porto/pkg/tlsconfig"
	"github.com/effective-security/porto/restserver"
	"github.com/effective-security/trustyca/api/client"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/config"
	"github.com/effective-security/trustyca/internal/db"
	"github.com/effective-security/x/fileutil/resolve"
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
// the CA over the backend gRPC client and the signed responses are cached
// until their NextUpdate.
type Service struct {
	server gserver.GServer
	cfg    *config.Configuration
	db     db.CaReadonlyDb
	cache  *ocspCache

	// the CA the OCSP requests are forwarded to: the one given to New, or
	// else a client of the backend created on the first request, since the
	// gRPC client blocks until the backend is reachable
	caLock   sync.Mutex
	ca       pb.CAServer
	caCloser io.Closer
	clients  client.Factory
}

// Factory returns a factory of the service
func Factory(server gserver.GServer) any {
	if server == nil {
		logger.Panic("aia.Factory: invalid parameter")
	}

	return func(cfg *config.Configuration,
		caDb db.CaReadonlyDb,
		clients client.Factory) error {
		svc, err := New(cfg, caDb, nil, clients)
		if err != nil {
			return err
		}
		svc.server = server
		server.AddService(svc)
		return nil
	}
}

// New returns the service over the CA tables. The CA is the server the
// OCSP requests are forwarded to; when it is nil, a client of the backend
// is created with the factory on the first request.
func New(cfg *config.Configuration, caDb db.CaReadonlyDb, ca pb.CAServer, clients client.Factory) (*Service, error) {
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
		ca:      ca,
		clients: clients,
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
	s.caLock.Lock()
	defer s.caLock.Unlock()
	if s.caCloser != nil {
		_ = s.caCloser.Close()
		s.caCloser = nil
		s.ca = nil
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

// caClient returns the CA the OCSP requests are forwarded to, creating the
// client of the backend on the first call: with the TLS certificate of
// `aia.client_tls` when it is set, else with the one of the client
// configuration. A backend that is not reachable fails the call, and the
// next request tries again.
func (s *Service) caClient() (pb.CAServer, error) {
	s.caLock.Lock()
	defer s.caLock.Unlock()
	if s.ca != nil {
		return s.ca, nil
	}
	if s.clients == nil {
		return nil, errors.New("CA client is not configured")
	}
	var ops []client.Option
	if tlsInfo := s.cfg.AIA.ClientTLS; !tlsInfo.Empty() {
		tlsCfg, err := tlsconfig.NewClientTLSFromFiles(
			resolve.ExpandPath(tlsInfo.CertFile),
			resolve.ExpandPath(tlsInfo.KeyFile),
			resolve.ExpandPath(tlsInfo.TrustedCAFile))
		if err != nil {
			return nil, errors.WithMessage(err, "unable to build the TLS configuration of the CA client")
		}
		ops = append(ops, client.WithTLS(tlsCfg))
	}
	ca, closer, err := s.clients.CAClient(config.BackendServerName, ops...)
	if err != nil {
		return nil, errors.WithMessage(err, "unable to create the CA client")
	}
	s.ca = ca
	s.caCloser = closer
	return ca, nil
}
