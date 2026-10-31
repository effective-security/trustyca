package ca

import (
	"context"
	"net/http"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/authctx"
	"github.com/effective-security/trustyca/privpb"
	"github.com/effective-security/xlog"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/emptypb"
)

// orgIDField is the field of a privpb request that names the org
const orgIDField = "OrgID"

// RegisterIssuer creates an issuer of the org (Backend.RegisterIssuer)
func (s *Service) RegisterIssuer(ctx context.Context, req *pb.RegisterIssuerRequest) (*pb.Issuer, error) {
	return forward(ctx, s, req, privpb.BackendServer.RegisterIssuer)
}

// ImportIssuer registers an existing issuer and its key
// (Backend.ImportIssuer)
func (s *Service) ImportIssuer(ctx context.Context, req *pb.ImportIssuerRequest) (*pb.Issuer, error) {
	return forward(ctx, s, req, privpb.BackendServer.ImportIssuer)
}

// ActivateIssuer activates a Pending issuer (Backend.ActivateIssuer)
func (s *Service) ActivateIssuer(ctx context.Context, req *pb.ActivateIssuerRequest) (*pb.Issuer, error) {
	return forward(ctx, s, req, privpb.BackendServer.ActivateIssuer)
}

// UpdateIssuer changes the settings or the status of an issuer
// (Backend.UpdateIssuer)
func (s *Service) UpdateIssuer(ctx context.Context, req *pb.UpdateIssuerRequest) (*pb.Issuer, error) {
	return forward(ctx, s, req, privpb.BackendServer.UpdateIssuer)
}

// GetIssuer returns an issuer of the org (Backend.GetIssuer)
func (s *Service) GetIssuer(ctx context.Context, req *pb.GetIssuerRequest) (*pb.Issuer, error) {
	return forward(ctx, s, req, privpb.BackendServer.GetIssuer)
}

// ListIssuers returns the issuers of the org (Backend.ListIssuers)
func (s *Service) ListIssuers(ctx context.Context, req *pb.ListIssuersRequest) (*pb.IssuersResponse, error) {
	return forward(ctx, s, req, privpb.BackendServer.ListIssuers)
}

// RegisterRoot registers a trust anchor of the org (Backend.RegisterRoot)
func (s *Service) RegisterRoot(ctx context.Context, req *pb.RegisterRootRequest) (*pb.RootCertificate, error) {
	return forward(ctx, s, req, privpb.BackendServer.RegisterRoot)
}

// ListRoots returns the trust anchors of the org (Backend.ListRoots)
func (s *Service) ListRoots(ctx context.Context, req *pb.ListRootsRequest) (*pb.RootsResponse, error) {
	return forward(ctx, s, req, privpb.BackendServer.ListRoots)
}

// RegisterProfile creates or replaces a profile (Backend.RegisterProfile)
func (s *Service) RegisterProfile(ctx context.Context, req *pb.RegisterProfileRequest) (*pb.CertProfile, error) {
	return forward(ctx, s, req, privpb.BackendServer.RegisterProfile)
}

// GetProfile returns a profile of the org (Backend.GetProfile)
func (s *Service) GetProfile(ctx context.Context, req *pb.GetProfileRequest) (*pb.CertProfile, error) {
	return forward(ctx, s, req, privpb.BackendServer.GetProfile)
}

// ListProfiles returns the profiles of the org (Backend.ListProfiles)
func (s *Service) ListProfiles(ctx context.Context, req *pb.ListProfilesRequest) (*pb.ProfilesResponse, error) {
	return forward(ctx, s, req, privpb.BackendServer.ListProfiles)
}

// DeleteProfile deletes a profile of the org (Backend.DeleteProfile)
func (s *Service) DeleteProfile(ctx context.Context, req *pb.DeleteProfileRequest) (*emptypb.Empty, error) {
	return forward(ctx, s, req, privpb.BackendServer.DeleteProfile)
}

// SignCertificate signs a certificate (Backend.SignCertificate)
func (s *Service) SignCertificate(ctx context.Context, req *pb.SignCertificateRequest) (*pb.CertificateResponse, error) {
	return forward(ctx, s, req, privpb.BackendServer.SignCertificate)
}

// GetCertificate returns a certificate of the org (Backend.GetCertificate)
func (s *Service) GetCertificate(ctx context.Context, req *pb.GetCertificateRequest) (*pb.CertificateResponse, error) {
	return forward(ctx, s, req, privpb.BackendServer.GetCertificate)
}

// ListCertificates returns the certificates of the org
// (Backend.ListCertificates)
func (s *Service) ListCertificates(ctx context.Context, req *pb.ListCertificatesRequest) (*pb.CertificatesResponse, error) {
	return forward(ctx, s, req, privpb.BackendServer.ListCertificates)
}

// UpdateCertificateLabel updates the label and metadata of a certificate
// (Backend.UpdateCertificateLabel)
func (s *Service) UpdateCertificateLabel(ctx context.Context, req *pb.UpdateCertificateLabelRequest) (*pb.CertificateResponse, error) {
	return forward(ctx, s, req, privpb.BackendServer.UpdateCertificateLabel)
}

// RevokeCertificate revokes a certificate of the org
// (Backend.RevokeCertificate)
func (s *Service) RevokeCertificate(ctx context.Context, req *pb.RevokeCertificateRequest) (*pb.RevokedCertificateResponse, error) {
	return forward(ctx, s, req, privpb.BackendServer.RevokeCertificate)
}

// ListRevokedCertificates returns the revoked certificates of the org
// (Backend.ListRevokedCertificates)
func (s *Service) ListRevokedCertificates(ctx context.Context, req *pb.ListRevokedCertificatesRequest) (*pb.RevokedCertificatesResponse, error) {
	return forward(ctx, s, req, privpb.BackendServer.ListRevokedCertificates)
}

// GetCRL returns the current CRL of an issuer of the org (Backend.GetCRL)
func (s *Service) GetCRL(ctx context.Context, req *pb.GetCrlRequest) (*pb.CrlResponse, error) {
	return forward(ctx, s, req, privpb.BackendServer.GetCRL)
}

// PublishCrls publishes CRLs (Backend.PublishCrls)
func (s *Service) PublishCrls(ctx context.Context, req *pb.PublishCrlsRequest) (*pb.CrlsResponse, error) {
	return forward(ctx, s, req, privpb.BackendServer.PublishCrls)
}

// SignOCSP signs an OCSP response (Backend.SignOCSP); the request names the
// issuer by its key hash and carries no tenant, so it is sent as is
func (s *Service) SignOCSP(ctx context.Context, req *pb.OCSPRequest) (*pb.OCSPResponse, error) {
	be, err := s.backendServer(ctx)
	if err != nil {
		return nil, err
	}
	res, err := be.SignOCSP(ctx, req)
	if err != nil {
		return nil, forwardedError(err)
	}
	return res, nil
}

// GetSummary returns the counts of the org's dashboard (Backend.GetSummary)
func (s *Service) GetSummary(ctx context.Context, req *pb.GetSummaryRequest) (*pb.SummaryResponse, error) {
	return forward(ctx, s, req, privpb.BackendServer.GetSummary)
}

// forward calls the method of the backend with the privpb counterpart of
// the public request and the context of the caller: the backend runs the
// method as that caller. The counterpart has the fields of the public
// request under the same numbers, so it is decoded from the encoding of
// the public request, and its OrgID is always the org of the caller's
// token, never a value the caller encoded in field 1. A nil request stays
// nil. A backend that cannot be reached is Unavailable, and the next call
// tries again.
func forward[Req proto.Message, PReq interface {
	*T
	proto.Message
}, T any, Res any](ctx context.Context, s *Service, req Req, method func(privpb.BackendServer, context.Context, PReq) (Res, error)) (Res, error) {
	var zero Res
	be, err := s.backendServer(ctx)
	if err != nil {
		return zero, err
	}
	var preq PReq
	if req.ProtoReflect().IsValid() {
		preq, err = counterpart[PReq](req, authctx.FromContext(ctx).OrgID().String())
		if err != nil {
			return zero, httperror.WrapWithCtx(ctx, err, "unable to forward the request")
		}
	}
	res, err := method(be, ctx, preq)
	if err != nil {
		return zero, forwardedError(err)
	}
	return res, nil
}

// counterpart returns the privpb request with the fields of the public
// request and the org
func counterpart[PReq interface {
	*T
	proto.Message
}, T any](req proto.Message, orgID string) (PReq, error) {
	data, err := proto.Marshal(req)
	if err != nil {
		return nil, errors.WithMessage(err, "unable to encode the request")
	}
	preq := PReq(new(T))
	err = proto.Unmarshal(data, preq)
	if err != nil {
		return nil, errors.WithMessage(err, "unable to decode the request")
	}
	m := preq.ProtoReflect()
	fd := m.Descriptor().Fields().ByName(orgIDField)
	if fd == nil {
		return nil, errors.Errorf("%s has no %s", m.Descriptor().FullName(), orgIDField)
	}
	m.Set(fd, protoreflect.ValueOfString(orgID))
	m.SetUnknown(nil)
	return preq, nil
}

// backendServer returns the backend; without a locator the CA is not
// configured, and a backend that cannot be reached is not available
func (s *Service) backendServer(ctx context.Context) (privpb.BackendServer, error) {
	if s.backend == nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.Unavailable, "CA is not configured")
	}
	be, err := s.backend.Backend()
	if err != nil {
		logger.ContextKV(ctx, xlog.ERROR,
			"reason", "backend",
			"err", err.Error())
		return nil, httperror.NewGrpcFromCtx(ctx, codes.Unavailable, "CA is not available")
	}
	return be, nil
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
