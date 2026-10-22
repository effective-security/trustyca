package cis

import (
	"cmp"
	"context"
	"database/sql"
	"time"

	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/trustyca/api/pb"
	core "github.com/effective-security/trustyca/internal/ca"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xlog"
	"google.golang.org/grpc/codes"
)

// defaultListLimit is used when a list request does not specify a limit
const defaultListLimit = 100

// GetRoots returns the published trust anchors, newest first: of the
// platform when the request names no org, else of the org. An unknown org
// has none.
func (s *Service) GetRoots(ctx context.Context, req *pb.ListRootsRequest) (*pb.RootsResponse, error) {
	if req == nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "missing request")
	}
	cursor, err := query.ParseCursor(req.Cursor)
	if err != nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid cursor")
	}
	q := &query.ListRootsRequest{
		Limit:  cmp.Or(req.Limit, defaultListLimit),
		Offset: req.Offset,
		Cursor: cursor,
	}
	if req.OrgID == "" {
		q.Platform = true
	} else {
		orgID, err := xdb.ParseID(req.OrgID)
		if err != nil {
			return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid org ID")
		}
		q.OrgID = orgID.UInt64()
	}
	res, err := s.db.ListRoots(ctx, q)
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "failed to list roots")
	}
	return res.Pb(), nil
}

// GetIssuer returns the public view of the issuer with the key identifier:
// its chain, status and the AIA, CRL and OCSP URLs of its settings with the
// key identifier in place of the placeholder. A Pending issuer has no
// certificate and is not found.
func (s *Service) GetIssuer(ctx context.Context, req *pb.GetIssuerInfoRequest) (*pb.IssuerInfo, error) {
	if req == nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "missing request")
	}
	if req.IKID == "" {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "missing IKID")
	}
	row, err := s.issuedIssuer(ctx, req.IKID)
	if err != nil {
		return nil, err
	}
	cfg, err := row.GetConfig()
	if err != nil {
		logger.ContextKV(ctx, xlog.ERROR,
			"reason", "issuer_config",
			"issuer_id", row.ID.UnderscoreString(),
			"ikid", row.Skid,
			"err", err.Error())
		return nil, httperror.NewGrpcFromCtx(ctx, codes.Internal, "unable to read issuer")
	}
	return &pb.IssuerInfo{
		Label:         row.Label,
		Type:          row.Type,
		Status:        row.Status,
		SKID:          row.Skid,
		Subject:       row.Subject,
		NotBefore:     row.NotBefore.String(),
		NotAfter:      row.NotAfter.String(),
		Certificate:   row.Pem,
		Intermediates: row.ChainPem,
		Root:          row.RootPem,
		CrlURL:        core.ExpandIssuerURL(cfg.CrlURL, row.Skid),
		OcspURL:       core.ExpandIssuerURL(cfg.OcspURL, row.Skid),
		AiaURL:        core.ExpandIssuerURL(cfg.AiaURL, row.Skid),
	}, nil
}

// GetCertificate returns the public view of a certificate by its ID, its
// Subject Key Identifier (the newest certificate of the key), its SHA-256
// thumbprint, or the key identifier of its issuer and its serial number.
// The tenancy and the client-owned fields (label, metadata, profile) are
// not part of the view.
func (s *Service) GetCertificate(ctx context.Context, req *pb.GetCertificateInfoRequest) (*pb.CertificateResponse, error) {
	if req == nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "missing request")
	}
	row, err := s.findCertificate(ctx, req)
	if err != nil {
		return nil, err
	}
	return &pb.CertificateResponse{
		Certificate: publicCertificate(row),
	}, nil
}

// GetCertificateStatus returns the revocation status of a certificate
// named as in GetCertificate: Active, Expired (an Active certificate whose
// validity has ended, before the cert_status task marks it) or Revoked
// with the time and reason of its revocation
func (s *Service) GetCertificateStatus(ctx context.Context, req *pb.GetCertificateInfoRequest) (*pb.CertificateStatusResponse, error) {
	if req == nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "missing request")
	}
	row, err := s.findCertificate(ctx, req)
	if err != nil {
		return nil, err
	}
	res := &pb.CertificateStatusResponse{
		IKID:         row.Ikid,
		SerialNumber: row.SerialNumber,
		Status:       row.Status,
		NotAfter:     row.NotAfter.String(),
	}
	switch {
	case row.Status == pb.CertificateStatus_Revoked:
		revoked, err := s.db.GetRevoked(ctx, &query.GetRevokedRequest{CertificateID: row.ID.UInt64()})
		if err != nil {
			if xdb.IsNotFoundError(err) {
				// a Revoked certificate always has its revocation: the two
				// are written in one transaction
				logger.ContextKV(ctx, xlog.ERROR,
					"reason", "revocation_missing",
					"id", row.ID.UnderscoreString(),
					"ikid", row.Ikid,
					"serial", row.SerialNumber)
				return nil, httperror.NewGrpcFromCtx(ctx, codes.Internal, "revocation record is missing")
			}
			return nil, httperror.WrapWithCtx(ctx, err, "unable to get revoked certificate")
		}
		res.RevokedAt = revoked.RevokedAt.String()
		res.Reason = revoked.Reason
	case row.Status == pb.CertificateStatus_Active && row.IsExpired(time.Now()):
		res.Status = pb.CertificateStatus_Expired
	}
	return res, nil
}

// GetCRL returns the current CRL of the issuer with the key identifier
func (s *Service) GetCRL(ctx context.Context, req *pb.GetCrlRequest) (*pb.CrlResponse, error) {
	if req == nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "missing request")
	}
	if req.IKID == "" {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "missing IKID")
	}
	row, err := s.db.GetCrl(ctx, req.IKID)
	if err != nil {
		if xdb.IsNotFoundError(err) {
			return nil, httperror.NewGrpcFromCtx(ctx, codes.NotFound, "CRL not found")
		}
		return nil, httperror.WrapWithCtx(ctx, err, "unable to find CRL")
	}
	return &pb.CrlResponse{
		Crl: publicCrl(row),
	}, nil
}

// issuedIssuer returns the issuer with the key identifier when it has a
// certificate; a Pending issuer, which has none, is not found
func (s *Service) issuedIssuer(ctx context.Context, ikid string) (*model.Issuer, error) {
	row, err := s.db.GetIssuerBySKID(ctx, ikid)
	if err != nil {
		if xdb.IsNotFoundError(err) {
			return nil, httperror.NewGrpcFromCtx(ctx, codes.NotFound, "issuer not found")
		}
		return nil, httperror.WrapWithCtx(ctx, err, "unable to find issuer")
	}
	if row.Status == pb.IssuerStatus_Pending || row.Pem == "" {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.NotFound, "issuer not found")
	}
	return row, nil
}

// findCertificate returns the certificate the request names, of any org:
// by ID, by issuer and serial number, by thumbprint, or the newest
// certificate of a Subject Key Identifier, in that precedence
func (s *Service) findCertificate(ctx context.Context, req *pb.GetCertificateInfoRequest) (*model.Certificate, error) {
	var row *model.Certificate
	var err error
	switch {
	case req.ID != "":
		var id xdb.ID
		id, err = xdb.ParseID(req.ID)
		if err != nil {
			return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid certificate ID")
		}
		row, err = s.db.GetCertificate(ctx, id.UInt64())
	case req.IssuerSerial != nil && (req.IssuerSerial.IKID != "" || req.IssuerSerial.SerialNumber != ""):
		if req.IssuerSerial.IKID == "" || req.IssuerSerial.SerialNumber == "" {
			return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "issuer key ID and serial number are required")
		}
		row, err = s.db.GetCertificateByIssuerSerial(ctx, req.IssuerSerial.IKID, req.IssuerSerial.SerialNumber)
	case req.Sha256 != "":
		row, err = s.db.GetCertificateBySha256(ctx, req.Sha256)
	case req.SKID != "":
		row, err = s.certificateBySKID(ctx, req.SKID)
	default:
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "certificate ID, SKID, SHA-256 or issuer serial is required")
	}
	if err != nil {
		if xdb.IsNotFoundError(err) {
			return nil, httperror.NewGrpcFromCtx(ctx, codes.NotFound, "certificate not found")
		}
		return nil, httperror.WrapWithCtx(ctx, err, "unable to find certificate")
	}
	return row, nil
}

// certificateBySKID returns the newest certificate of the key among every
// org and the platform, since a renewed key keeps its SKID
func (s *Service) certificateBySKID(ctx context.Context, skid string) (*model.Certificate, error) {
	res, err := s.db.ListCertificates(ctx, &query.ListCertificatesRequest{
		AllOrgs: true,
		SKID:    skid,
		Limit:   1,
	})
	if err != nil {
		return nil, err
	}
	if len(res.Rows) == 0 {
		return nil, xdb.CheckNotFoundError(sql.ErrNoRows, "certificate", skid)
	}
	return res.Rows[0], nil
}

// publicCertificate returns the view of a certificate the CIS serves: the
// certificate, its chain and its status, without the tenancy, the label,
// the metadata and the profile, which belong to the org
func publicCertificate(m *model.Certificate) *pb.Certificate {
	res := m.Pb()
	res.OrgID = ""
	res.ProjectID = ""
	res.Profile = ""
	res.Label = ""
	res.Metadata = nil
	return res
}

// publicCrl returns the view of a CRL the CIS serves, without the org
func publicCrl(m *model.Crl) *pb.Crl {
	res := m.Pb()
	res.OrgID = ""
	return res
}
