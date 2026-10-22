package ca

import (
	"context"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/internal/events"
	"github.com/effective-security/trustyca/internal/metricskey"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xlog"
	"google.golang.org/grpc/codes"
)

// certificateSelector names the certificate a request refers to: by ID, by
// Subject Key Identifier, by SHA-256 thumbprint, or by the key identifier
// of its issuer and its serial number; with a project, the certificate must
// belong to it
type certificateSelector struct {
	id           string
	skid         string
	sha256       string
	issuerSerial *pb.IssuerSerial
	projectID    xdb.ID
}

// GetCertificate returns a certificate of the org by its ID, its Subject
// Key Identifier (the newest one of the key), its SHA-256 thumbprint, or
// the key identifier of its issuer and its serial number. A certificate of
// another org, or of a project the caller cannot read, is not found.
func (s *Service) GetCertificate(ctx context.Context, req *pb.GetCertificateRequest) (*pb.CertificateResponse, error) {
	if req == nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "missing request")
	}
	orgID, err := s.tenantOrg(ctx, req.OrgID)
	if err != nil {
		return nil, err
	}
	row, err := s.findCertificate(ctx, orgID, &certificateSelector{
		id:           req.ID,
		skid:         req.SKID,
		sha256:       req.Sha256,
		issuerSerial: req.IssuerSerial,
	}, pb.CA_GetCertificate_FullMethodName)
	if err != nil {
		return nil, err
	}
	return &pb.CertificateResponse{
		Certificate: row.Pb(),
	}, nil
}

// ListCertificates returns the certificates of the org, newest first: of
// the project of the request, or of the org-wide scope and every project
// the caller may read (DESIGN.md section 3.3)
func (s *Service) ListCertificates(ctx context.Context, req *pb.ListCertificatesRequest) (*pb.CertificatesResponse, error) {
	if req == nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "missing request")
	}
	orgID, err := s.tenantOrg(ctx, req.OrgID)
	if err != nil {
		return nil, err
	}
	projectID, err := s.tenantProject(ctx, orgID, req.ProjectID)
	if err != nil {
		return nil, err
	}
	cursor, err := listCursor(ctx, req.Cursor)
	if err != nil {
		return nil, err
	}
	expiringBefore, err := parseTime(ctx, req.ExpiringBefore, "ExpiringBefore")
	if err != nil {
		return nil, err
	}
	q := &query.ListCertificatesRequest{
		OrgID:     orgID.UInt64(),
		ProjectID: projectID.UInt64(),
		IKID:      req.IKID,
		Profile:   req.Profile,
		Status:    req.Status,
		Limit:     listLimit(req.Limit),
		Offset:    req.Offset,
		Cursor:    cursor,
	}
	if !expiringBefore.IsZero() {
		q.ExpiringBefore = &expiringBefore
	}
	if projectID.IsZero() {
		q.ProjectIDs, err = s.listProjects(ctx, orgID)
		if err != nil {
			return nil, err
		}
	}
	res, err := s.db.ListCertificates(ctx, q)
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "failed to list certificates")
	}
	return res.Pb(), nil
}

// UpdateCertificateLabel replaces the label a client gave a certificate,
// and its client metadata when the request carries any. The request names
// the project of the certificate when the caller's role is granted there
// only (the interceptor authorizes that scope); a certificate of another
// project is then not found. There is no event type for the change: it is
// logged, not recorded in the audit trail.
func (s *Service) UpdateCertificateLabel(ctx context.Context, req *pb.UpdateCertificateLabelRequest) (*pb.CertificateResponse, error) {
	if req == nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "missing request")
	}
	if len(req.Label) > model.MaxLenForName {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid label length")
	}
	orgID, err := s.tenantOrg(ctx, req.OrgID)
	if err != nil {
		return nil, err
	}
	if req.ID == "" {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "missing certificate ID")
	}
	projectID, err := s.requestProject(ctx, orgID, req.ProjectID)
	if err != nil {
		return nil, err
	}
	row, err := s.findCertificate(ctx, orgID, &certificateSelector{
		id:        req.ID,
		projectID: projectID,
	}, pb.CA_UpdateCertificateLabel_FullMethodName)
	if err != nil {
		return nil, err
	}
	label := req.Label
	upd := &query.UpdateCertificateRequest{
		ID:    row.ID.UInt64(),
		OrgID: orgID.UInt64(),
		Label: &label,
	}
	if req.Metadata != nil {
		upd.Metadata = xdb.Metadata(req.Metadata)
	}
	res, err := s.db.UpdateCertificate(ctx, upd)
	if err != nil {
		if xdb.IsNotFoundError(err) {
			return nil, httperror.NewGrpcFromCtx(ctx, codes.NotFound, "certificate not found")
		}
		return nil, httperror.WrapWithCtx(ctx, err, "failed to update certificate")
	}
	logger.ContextKV(ctx, xlog.NOTICE,
		"status", "certificate_updated",
		"id", res.ID.UnderscoreString(),
		"org_id", res.OrgID.UnderscoreString(),
		"project_id", res.ProjectID.UnderscoreString(),
		"label", res.Label)
	return &pb.CertificateResponse{
		Certificate: res.Pb(),
	}, nil
}

// RevokeCertificate revokes a certificate of the org, named by its ID, its
// Subject Key Identifier or its issuer and serial number: the revocation
// and the status of the certificate are written in one transaction
// (db.RevokeCertificate), then the CertificateRevoked event is recorded. A
// revoked certificate is refused with a precondition failure, and the
// reason RemoveFromCRL, which releases a certificate from hold (RFC 5280
// section 5.3.1), is refused since hold removal is not implemented. The
// request names the project of the certificate when the caller's role is
// granted there only; a certificate of another project is then not found.
func (s *Service) RevokeCertificate(ctx context.Context, req *pb.RevokeCertificateRequest) (*pb.RevokedCertificateResponse, error) {
	if req == nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "missing request")
	}
	if _, ok := pb.ReasonCode_Enum_name[int32(req.Reason)]; !ok {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid reason")
	}
	if req.Reason == pb.ReasonCode_RemoveFromCRL {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "reason %s releases a certificate from hold: not a revocation reason", req.Reason.String())
	}
	if len(req.ReasonText) > model.MaxLenForName {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid reason text length")
	}
	orgID, err := s.tenantOrg(ctx, req.OrgID)
	if err != nil {
		return nil, err
	}
	projectID, err := s.requestProject(ctx, orgID, req.ProjectID)
	if err != nil {
		return nil, err
	}
	row, err := s.findCertificate(ctx, orgID, &certificateSelector{
		id:           req.ID,
		skid:         req.SKID,
		issuerSerial: req.IssuerSerial,
		projectID:    projectID,
	}, pb.CA_RevokeCertificate_FullMethodName)
	if err != nil {
		return nil, err
	}
	if row.Status == pb.CertificateStatus_Revoked {
		return nil, preconditionFailed(ctx, "certificate is already revoked")
	}
	res, err := s.db.RevokeCertificate(ctx, &query.RevokeCertificateRequest{
		CertificateID: row.ID.UInt64(),
		OrgID:         orgID.UInt64(),
		RevokedAt:     time.Now(),
		Reason:        req.Reason,
		ReasonText:    req.ReasonText,
	})
	if err != nil {
		switch {
		case errors.Is(err, db.ErrAlreadyRevoked):
			return nil, preconditionFailed(ctx, "certificate is already revoked")
		case xdb.IsNotFoundError(err):
			return nil, httperror.NewGrpcFromCtx(ctx, codes.NotFound, "certificate not found")
		}
		logger.ContextKV(ctx, xlog.ERROR,
			"reason", "revoke_certificate",
			"id", row.ID.UnderscoreString(),
			"ikid", row.Ikid,
			"serial", row.SerialNumber,
			"err", err.Error())
		return nil, httperror.WrapWithCtx(ctx, err, "failed to revoke certificate")
	}
	metricskey.CACertRevoked.IncrCounter(1, res.Ikid)

	logger.ContextKV(ctx, xlog.NOTICE,
		"status", "revoked",
		"id", res.CertificateID.UnderscoreString(),
		"org_id", res.OrgID.UnderscoreString(),
		"project_id", res.ProjectID.UnderscoreString(),
		"ikid", res.Ikid,
		"serial", res.SerialNumber,
		"subject", res.Subject,
		"revocation_reason", res.Reason.String())
	events.New(ctx, ServiceName, pb.EventType_CertificateRevoked, "Certificate revoked").
		Org(orgID).
		Project(res.ProjectID).
		Reference(res.CertificateID).
		Description("certificate %q revoked: %s", res.Subject, res.Reason.String()).
		Emit(s.orgs)
	return &pb.RevokedCertificateResponse{
		Revoked: res.Pb(),
	}, nil
}

// ListRevokedCertificates returns the revoked certificates of the org with
// their revocation, newest revocation first, in the scope of the request
// as ListCertificates does
func (s *Service) ListRevokedCertificates(ctx context.Context, req *pb.ListRevokedCertificatesRequest) (*pb.RevokedCertificatesResponse, error) {
	if req == nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "missing request")
	}
	orgID, err := s.tenantOrg(ctx, req.OrgID)
	if err != nil {
		return nil, err
	}
	projectID, err := s.tenantProject(ctx, orgID, req.ProjectID)
	if err != nil {
		return nil, err
	}
	cursor, err := listCursor(ctx, req.Cursor)
	if err != nil {
		return nil, err
	}
	q := &query.ListRevokedCertificatesRequest{
		OrgID:     orgID.UInt64(),
		ProjectID: projectID.UInt64(),
		IKID:      req.IKID,
		Limit:     listLimit(req.Limit),
		Offset:    req.Offset,
		Cursor:    cursor,
	}
	if projectID.IsZero() {
		q.ProjectIDs, err = s.listProjects(ctx, orgID)
		if err != nil {
			return nil, err
		}
	}
	res, err := s.db.ListRevokedCertificates(ctx, q)
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "failed to list revoked certificates")
	}
	return res.Pb(), nil
}

// findCertificate returns the certificate of the org the selector names,
// when the caller may call the method on it (rowAccess): by ID, by issuer
// and serial number, by thumbprint, or the newest certificate of a Subject
// Key Identifier among those the caller may read. A certificate of another
// org, of the platform, of a project the caller cannot read or, when the
// selector names a project, of another project is not found.
func (s *Service) findCertificate(ctx context.Context, orgID xdb.ID, sel *certificateSelector, method string) (*model.Certificate, error) {
	var row *model.Certificate
	var err error
	switch {
	case sel.id != "":
		var id xdb.ID
		id, err = parseID(ctx, sel.id, "certificate ID")
		if err != nil {
			return nil, err
		}
		row, err = s.db.GetCertificate(ctx, id.UInt64())
	case sel.issuerSerial != nil && (sel.issuerSerial.IKID != "" || sel.issuerSerial.SerialNumber != ""):
		if sel.issuerSerial.IKID == "" || sel.issuerSerial.SerialNumber == "" {
			return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "issuer key ID and serial number are required")
		}
		row, err = s.db.GetCertificateByIssuerSerial(ctx, sel.issuerSerial.IKID, sel.issuerSerial.SerialNumber)
	case sel.sha256 != "":
		row, err = s.db.GetCertificateBySha256(ctx, sel.sha256)
	case sel.skid != "":
		row, err = s.certificateBySKID(ctx, orgID, sel.projectID, sel.skid)
	default:
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "certificate ID, SKID, SHA-256 or issuer serial is required")
	}
	if err != nil {
		if xdb.IsNotFoundError(err) {
			return nil, httperror.NewGrpcFromCtx(ctx, codes.NotFound, "certificate not found")
		}
		return nil, httperror.WrapWithCtx(ctx, err, "unable to find certificate")
	}
	if row == nil || row.OrgID.UInt64() != orgID.UInt64() {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.NotFound, "certificate not found")
	}
	if !sel.projectID.IsZero() && row.ProjectID.UInt64() != sel.projectID.UInt64() {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.NotFound, "certificate not found")
	}
	err = s.rowAccess(ctx, orgID, row.ProjectID, method, "certificate")
	if err != nil {
		return nil, err
	}
	return row, nil
}

// certificateBySKID returns the newest certificate of the org with the
// Subject Key Identifier, or nil when there is none: of the project when
// the request names one, otherwise among the org-wide ones and those of
// the projects the caller may read (the project of a restricted API key, or
// the projects of the caller's grants). A key is renewed under the same
// identifier, so the identifier is not unique, and the scope is filtered
// before the newest one is taken.
func (s *Service) certificateBySKID(ctx context.Context, orgID, projectID xdb.ID, skid string) (*model.Certificate, error) {
	q := &query.ListCertificatesRequest{
		OrgID: orgID.UInt64(),
		SKID:  skid,
		Limit: 1,
	}
	if !projectID.IsZero() {
		q.ProjectID = projectID.UInt64()
	} else {
		keyProjectID, err := s.tenantProject(ctx, orgID, "")
		if err != nil {
			return nil, err
		}
		if keyProjectID.IsZero() {
			q.ProjectIDs, err = s.listProjects(ctx, orgID)
			if err != nil {
				return nil, err
			}
		} else {
			q.ProjectIDs = []uint64{keyProjectID.UInt64()}
		}
	}
	res, err := s.db.ListCertificates(ctx, q)
	if err != nil {
		return nil, err
	}
	if len(res.Rows) == 0 {
		return nil, nil
	}
	return res.Rows[0], nil
}
