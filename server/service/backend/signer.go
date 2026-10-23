package backend

import (
	"context"
	"encoding/pem"
	"strings"
	"time"

	"github.com/effective-security/trustyca/privpb"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/trustyca/api/pb"
	core "github.com/effective-security/trustyca/internal/ca"
	"github.com/effective-security/trustyca/internal/ca/pbconv"
	"github.com/effective-security/trustyca/internal/db"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/internal/events"
	"github.com/effective-security/trustyca/internal/metricskey"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/authority"
	"github.com/effective-security/xpki/csr"
	"golang.org/x/crypto/ocsp"
	"google.golang.org/grpc/codes"
)

// csrPEMType is the PEM block type of a PKCS#10 request
const csrPEMType = "CERTIFICATE REQUEST"

// signRequestErrorMarkers are the fragments of the signing errors that a
// client can fix by changing its request; any other signing error is the
// issuer's
var signRequestErrorMarkers = []string{
	"invalid",
	"not allowed",
	"missing",
	"parse",
	"CSR",
	"does not match",
	"disallows",
	"exceeds",
	"earlier than allowed",
	"unsupported profile",
}

// SignCertificate signs a certificate request with the issuer of the
// profile, resolved in the scope of the request (DESIGN.md section 6), and
// records the certificate with its issue event in one transaction.
func (s *Service) SignCertificate(ctx context.Context, req *privpb.SignCertificateRequest) (*pb.CertificateResponse, error) {
	if req == nil || len(req.Request) == 0 {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "missing request")
	}
	if req.Profile == "" {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "missing profile")
	}
	if len(req.Label) > model.MaxLenForName {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid label length")
	}
	err := s.requireCA(ctx)
	if err != nil {
		return nil, err
	}

	orgID, err := s.scope.Org(ctx, req.OrgID)
	if err != nil {
		return nil, err
	}
	projectID, err := s.scope.Project(ctx, orgID, req.ProjectID)
	if err != nil {
		return nil, err
	}

	pemReq, err := requestPEM(ctx, req.RequestFormat, req.Request)
	if err != nil {
		return nil, err
	}
	res, err := s.resolve(ctx, orgID, projectID, req.Profile, req.IssuerLabel)
	if err != nil {
		return nil, err
	}
	issuer := res.Issuer

	cr := csr.SignRequest{
		Request: pemReq,
		Profile: res.ProfileName,
		SAN:     req.SAN,
		Subject: subjectOf(req.Subject),
	}
	cr.Extensions, err = pbconv.ExtensionsFromPb(req.Extensions)
	if err != nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "%s", err.Error())
	}
	cr.NotBefore, err = parseTime(ctx, req.NotBefore, "NotBefore")
	if err != nil {
		return nil, err
	}
	cr.NotAfter, err = parseTime(ctx, req.NotAfter, "NotAfter")
	if err != nil {
		return nil, err
	}

	signStart := time.Now()
	crt, crtPEM, err := issuer.Sign(cr)
	if err != nil {
		logger.ContextKV(ctx, xlog.WARNING,
			"reason", "sign",
			"issuer_id", res.Row.ID.UnderscoreString(),
			"issuer", issuer.Label(),
			"profile", req.Profile,
			"err", err.Error())
		metricskey.CAFailSignCert.IncrCounter(1, issuer.Label(), req.Profile, orgID.String())

		if isSignRequestError(err) {
			return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "failed to sign certificate: %s", err.Error())
		}
		return nil, httperror.WrapWithCtx(ctx, err, "failed to sign certificate")
	}
	metricskey.CACertIssued.IncrCounter(1, issuer.Label(), req.Profile, orgID.String())

	mcert := model.NewCertificate(crt, orgID, projectID, req.Profile, string(crtPEM), issuer.PEM(), req.Label, nil, req.Metadata)
	evt := events.New(ctx, EventSource, pb.EventType_CertificateIssued, "Certificate issued").
		Org(orgID).
		Project(projectID).
		Description("certificate %q issued by %q with profile %q", mcert.Subject, issuer.Label(), req.Profile)

	registered, err := s.db.RegisterCertificate(ctx, mcert, evt.Model())
	if err != nil {
		logger.ContextKV(ctx, xlog.ERROR,
			"reason", "register_certificate",
			"issuer_id", res.Row.ID.UnderscoreString(),
			"issuer", issuer.Label(),
			"sha256", mcert.Sha256,
			"err", err.Error())
		if db.IsUniqueViolation(err, db.UniqueCertificatePrefix) {
			return nil, httperror.NewGrpcFromCtx(ctx, codes.AlreadyExists, "certificate is already registered")
		}
		return nil, httperror.WrapWithCtx(ctx, err, "failed to register certificate")
	}
	metricskey.CASignLatency.MeasureSince(signStart, issuer.Label(), req.Profile)

	logger.ContextKV(ctx, xlog.NOTICE,
		"status", "signed",
		"id", registered.ID.UnderscoreString(),
		"org_id", registered.OrgID.UnderscoreString(),
		"project_id", registered.ProjectID.UnderscoreString(),
		"issuer_id", res.Row.ID.UnderscoreString(),
		"issuer", issuer.Label(),
		"profile", registered.Profile,
		"subject", registered.Subject,
		"sha256", registered.Sha256,
	)
	return &pb.CertificateResponse{
		Certificate: registered.Pb(),
	}, nil
}

// SignOCSP signs an OCSP response for the certificate of the request:
// good for a registered certificate, revoked with the reason and time of its
// revocation, and unknown for a serial the issuer never registered.
func (s *Service) SignOCSP(ctx context.Context, req *pb.OCSPRequest) (*pb.OCSPResponse, error) {
	if req == nil || len(req.Der) == 0 {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "missing request")
	}
	err := s.requireCA(ctx)
	if err != nil {
		return nil, err
	}
	ocspReq, err := ocsp.ParseRequest(req.Der)
	if err != nil || ocspReq.SerialNumber == nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid request")
	}

	issuer, err := s.ocspIssuer(ctx, ocspReq)
	if err != nil {
		return nil, err
	}
	ikid := issuer.SubjectKID()
	serial := ocspReq.SerialNumber.String()

	oreq := &authority.OCSPSignRequest{
		SerialNumber: ocspReq.SerialNumber,
		Status:       authority.OCSPStatusGood,
		IssuerHash:   ocspReq.HashAlgorithm,
	}
	crt, err := s.db.GetCertificateByIssuerSerial(ctx, ikid, serial)
	switch {
	case err != nil && xdb.IsNotFoundError(err):
		oreq.Status = authority.OCSPStatusUnknown
	case err != nil:
		return nil, httperror.WrapWithCtx(ctx, err, "unable to get certificate")
	case crt.Status == pb.CertificateStatus_Revoked:
		revoked, err := s.db.GetRevoked(ctx, &query.GetRevokedRequest{CertificateID: crt.ID.UInt64()})
		if err != nil {
			if xdb.IsNotFoundError(err) {
				// a Revoked certificate always has its revocation: the two
				// are written in one transaction
				logger.ContextKV(ctx, xlog.ERROR,
					"reason", "revocation_missing",
					"id", crt.ID.UnderscoreString(),
					"ikid", ikid,
					"serial", serial)
				return nil, httperror.NewGrpcFromCtx(ctx, codes.Internal, "revocation record is missing")
			}
			return nil, httperror.WrapWithCtx(ctx, err, "unable to get revoked certificate")
		}
		oreq.Status = authority.OCSPStatusRevoked
		oreq.Reason = int(revoked.Reason)
		oreq.RevokedAt = revoked.RevokedAt.UTC()
	}

	logger.ContextKV(ctx, xlog.TRACE,
		"ikid", ikid,
		"serial", serial,
		"status", oreq.Status)

	der, err := issuer.SignOCSP(oreq)
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "unable to sign OCSP")
	}
	metricskey.CAOcspSigned.IncrCounter(1, ikid, oreq.Status)

	return &pb.OCSPResponse{Der: der}, nil
}

// resolve returns the issuer and the profile of a sign request in the
// scope, mapping the registry errors to the status codes of the API: a
// missing profile or issuer is not found, a profile and an issuer that do
// not go together is a bad request, an issuer that does not sign is a
// precondition failure, and an issuer that does not load is internal.
func (s *Service) resolve(ctx context.Context, orgID, projectID xdb.ID, profile, issuerLabel string) (*core.Resolution, error) {
	res, err := s.registry.Resolve(ctx, &core.ResolveRequest{
		OrgID:       orgID,
		ProjectID:   projectID,
		Profile:     profile,
		IssuerLabel: issuerLabel,
	})
	if err == nil {
		return res, nil
	}
	switch {
	case errors.Is(err, core.ErrProfileNotFound):
		return nil, httperror.NewGrpcFromCtx(ctx, codes.NotFound, "profile not found: %s", profile)
	case errors.Is(err, core.ErrIssuerNotFound):
		if issuerLabel != "" {
			return nil, httperror.NewGrpcFromCtx(ctx, codes.NotFound, "issuer not found: %s", issuerLabel)
		}
		return nil, httperror.NewGrpcFromCtx(ctx, codes.NotFound, "issuer not found for profile: %s", profile)
	case errors.Is(err, core.ErrIssuerLabelRequired):
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "issuer label is required for profile: %s", profile)
	case errors.Is(err, core.ErrIssuerMismatch):
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "issuer %q does not serve the profile: %s", issuerLabel, profile)
	case errors.Is(err, core.ErrProfileNotAllowed):
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "issuer %q does not support the profile: %s", issuerLabel, profile)
	case errors.Is(err, core.ErrIssuerNotActive):
		return nil, preconditionFailed(ctx, "issuer is not active")
	}
	logger.ContextKV(ctx, xlog.ERROR,
		"reason", "load_issuer",
		"org_id", orgID.UnderscoreString(),
		"project_id", projectID.UnderscoreString(),
		"profile", profile,
		"issuer", issuerLabel,
		"err", err.Error())
	return nil, httperror.NewGrpcFromCtx(ctx, codes.Internal, "unable to load issuer")
}

// ocspIssuer resolves the issuer of an OCSP request by the hash of its key,
// or of its name
func (s *Service) ocspIssuer(ctx context.Context, ocspReq *ocsp.Request) (*authority.Issuer, error) {
	var issuer *authority.Issuer
	var err error
	switch {
	case len(ocspReq.IssuerKeyHash) > 0:
		issuer, _, err = s.registry.IssuerByKeyHash(ctx, ocspReq.HashAlgorithm, ocspReq.IssuerKeyHash)
	case len(ocspReq.IssuerNameHash) > 0:
		issuer, _, err = s.registry.IssuerByNameHash(ctx, ocspReq.HashAlgorithm, ocspReq.IssuerNameHash)
	default:
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "issuer not specified")
	}
	if err != nil {
		if errors.Is(err, core.ErrIssuerNotFound) || errors.Is(err, core.ErrIssuerNotActive) {
			return nil, httperror.NewGrpcFromCtx(ctx, codes.NotFound, "issuer not found")
		}
		logger.ContextKV(ctx, xlog.ERROR,
			"reason", "load_issuer",
			"err", err.Error())
		return nil, httperror.NewGrpcFromCtx(ctx, codes.Internal, "unable to load issuer")
	}
	return issuer, nil
}

// requestPEM returns the PEM encoding of the certificate request
func requestPEM(ctx context.Context, format pb.EncodingFormat_Enum, request []byte) (string, error) {
	switch format {
	case pb.EncodingFormat_PEM:
		return string(request), nil
	case pb.EncodingFormat_DER:
		return string(pem.EncodeToMemory(&pem.Block{Type: csrPEMType, Bytes: request})), nil
	default:
		return "", httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "unsupported request format: %s", format.String())
	}
}

// subjectOf converts the subject override of a request
func subjectOf(subject *pb.X509Subject) *csr.X509Subject {
	if subject == nil {
		return nil
	}
	res := &csr.X509Subject{
		CommonName:   subject.CommonName,
		Names:        make([]csr.X509Name, len(subject.Names)),
		SerialNumber: subject.SerialNumber,
	}
	for i, n := range subject.Names {
		res.Names[i] = csr.X509Name{
			Country:            n.Country,
			Province:           n.State,
			Locality:           n.Locality,
			Organization:       n.Organisation,
			OrganizationalUnit: n.OrganisationalUnit,
			SerialNumber:       n.SerialNumber,
		}
	}
	return res
}

// isSignRequestError returns true when the signing error is the request's
func isSignRequestError(err error) bool {
	msg := err.Error()
	for _, marker := range signRequestErrorMarkers {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}
