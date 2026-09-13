package ui

import (
	"github.com/effective-security/porto/gserver"
	"github.com/effective-security/porto/restserver"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/config"
	"github.com/effective-security/xlog"
)

// ServiceName provides the Service Name for this package
const ServiceName = "ui"

var logger = xlog.NewPackageLogger("github.com/effective-security/trustyca/server/service", ServiceName)

// Service serves the static test pages: the ALIVE index, the login page
// that starts the OAuth flow, the page shown after authentication, and the
// Stripe checkout page. The pages are embedded in the binary and rendered
// with the public keys (reCAPTCHA site key, Stripe publishable key) taken
// from the configuration.
type Service struct {
	server gserver.GServer
	cfg    *config.Configuration
}

// Factory returns a factory of the service
func Factory(server gserver.GServer) any {
	if server == nil {
		logger.Panic("ui.Factory: invalid parameter")
	}

	return func(cfg *config.Configuration) {
		svc := New(cfg)
		svc.server = server
		server.AddService(svc)
	}
}

// New returns the service for the configuration,
// without registering it with a server; used by tests.
func New(cfg *config.Configuration) *Service {
	return &Service{
		cfg: cfg,
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

// RegisterRoute adds the UI pages to the overall URL router
func (s *Service) RegisterRoute(r restserver.Router) {
	r.GET("/", s.indexHandler())
	r.GET(pb.PathForLoginPage, s.PageHandler(pb.PathForLoginPage))
	r.GET(pb.PathForAuthenticatedPage, s.PageHandler(pb.PathForAuthenticatedPage))
	r.GET(pb.PathForPaymentPage, s.PageHandler(pb.PathForPaymentPage))
}
