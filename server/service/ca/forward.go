package ca

import (
	"context"
	"net/http"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/privpb"
	"github.com/effective-security/xlog"
	"google.golang.org/grpc/codes"
)

// RegisterIssuer creates an issuer of the org in the backend
// (Backend.RegisterIssuer)
func (s *Service) RegisterIssuer(ctx context.Context, req *pb.RegisterIssuerRequest) (*pb.Issuer, error) {
	return forward(ctx, s, req, privpb.BackendServer.RegisterIssuer)
}

// ImportIssuer registers an existing issuer and its key in the backend
// (Backend.ImportIssuer)
func (s *Service) ImportIssuer(ctx context.Context, req *pb.ImportIssuerRequest) (*pb.Issuer, error) {
	return forward(ctx, s, req, privpb.BackendServer.ImportIssuer)
}

// ActivateIssuer activates a Pending issuer in the backend
// (Backend.ActivateIssuer)
func (s *Service) ActivateIssuer(ctx context.Context, req *pb.ActivateIssuerRequest) (*pb.Issuer, error) {
	return forward(ctx, s, req, privpb.BackendServer.ActivateIssuer)
}

// UpdateIssuer changes an issuer in the backend, whose registry must see
// an issuer stop signing at once (Backend.UpdateIssuer)
func (s *Service) UpdateIssuer(ctx context.Context, req *pb.UpdateIssuerRequest) (*pb.Issuer, error) {
	return forward(ctx, s, req, privpb.BackendServer.UpdateIssuer)
}

// SignCertificate signs a certificate in the backend
// (Backend.SignCertificate)
func (s *Service) SignCertificate(ctx context.Context, req *pb.SignCertificateRequest) (*pb.CertificateResponse, error) {
	return forward(ctx, s, req, privpb.BackendServer.SignCertificate)
}

// PublishCrls publishes CRLs in the backend (Backend.PublishCrls)
func (s *Service) PublishCrls(ctx context.Context, req *pb.PublishCrlsRequest) (*pb.CrlsResponse, error) {
	return forward(ctx, s, req, privpb.BackendServer.PublishCrls)
}

// SignOCSP signs an OCSP response in the backend (Backend.SignOCSP)
func (s *Service) SignOCSP(ctx context.Context, req *pb.OCSPRequest) (*pb.OCSPResponse, error) {
	return forward(ctx, s, req, privpb.BackendServer.SignOCSP)
}

// forward calls the method of the backend with the request and the
// context of the caller: the backend runs the method as that caller. A
// backend that cannot be reached is Unavailable, and the next call tries
// again.
func forward[Req, Res any](ctx context.Context, s *Service, req Req, method func(privpb.BackendServer, context.Context, Req) (Res, error)) (Res, error) {
	var zero Res
	if s.backend == nil {
		return zero, httperror.NewGrpcFromCtx(ctx, codes.Unavailable, "CA is not configured")
	}
	be, err := s.backend.Backend()
	if err != nil {
		logger.ContextKV(ctx, xlog.ERROR,
			"reason", "backend",
			"err", err.Error())
		return zero, httperror.NewGrpcFromCtx(ctx, codes.Unavailable, "CA is not available")
	}
	res, err := method(be, ctx, req)
	if err != nil {
		return zero, forwardedError(err)
	}
	return res, nil
}

// forwardedError restores the HTTP status of a refusal that the state of
// the org or the issuer causes when it comes back from a remote backend:
// the CA answers every FailedPrecondition with preconditionFailed (HTTP 409
// conflict), while porto gives a converted gRPC FailedPrecondition the HTTP
// status of its own table (400 bad_request)
func forwardedError(err error) error {
	var e *httperror.Error
	if errors.As(err, &e) && e.RPCStatus == codes.FailedPrecondition {
		e.HTTPStatus = http.StatusConflict
		e.Code = httperror.CodeConflict
	}
	return err
}
