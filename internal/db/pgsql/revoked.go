package pgsql

import (
	"context"
	"fmt"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/internal/db/schema"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xlog"
)

// ErrAlreadyRevoked is returned by RevokeCertificate for a certificate whose
// status is Revoked
var ErrAlreadyRevoked = errors.New("certificate is already revoked")

// RevokeCertificate records the revocation of a certificate of the exact org
// scope and sets its status to Revoked in one transaction. The revocation
// copies the issuer, serial number, expiry and tenancy of the certificate
// row.
func (p *Provider) RevokeCertificate(ctx context.Context, req *query.RevokeCertificateRequest) (*model.RevokedCertificate, error) {
	if req.CertificateID == 0 {
		return nil, errors.New("certificate ID is required")
	}
	if len(req.ReasonText) > model.MaxLenForName {
		return nil, errors.Errorf("invalid reason text length: %d", len(req.ReasonText))
	}
	revokedAt := req.RevokedAt
	if revokedAt.IsZero() {
		revokedAt = time.Now()
	}

	defer DbMeasureSince(time.Now())

	tx, err := p.BeginTx(ctx, nil)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer func() {
		err := tx.Close()
		if err != nil {
			logger.ContextKV(ctx, xlog.ERROR, "reason", "close", "err", err.Error())
		}
	}()

	txProvider := tx.(*Provider)
	crt, err := txProvider.getCertificateForUpdate(ctx, req.CertificateID, query.OrgArg(req.OrgID))
	if err != nil {
		return nil, err
	}
	if crt.Status == pb.CertificateStatus_Revoked {
		return nil, errors.WithStack(ErrAlreadyRevoked)
	}

	revoked, err := txProvider.registerRevoked(ctx, &model.Revoked{
		OrgID:         crt.OrgID,
		ProjectID:     crt.ProjectID,
		CertificateID: crt.ID,
		Ikid:          crt.Ikid,
		SerialNumber:  crt.SerialNumber,
		NotAfter:      crt.NotAfter,
		RevokedAt:     xdb.UTC(revokedAt),
		Reason:        req.Reason,
		ReasonText:    req.ReasonText,
	})
	if err != nil {
		return nil, errors.WithMessage(err, "unable to register revocation")
	}

	crt, err = txProvider.updateCertificateStatus(ctx, crt.ID, pb.CertificateStatus_Revoked)
	if err != nil {
		return nil, errors.WithMessage(err, "unable to update certificate status")
	}

	err = tx.Commit()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return model.NewRevokedCertificate(crt, revoked), nil
}

// registerRevoked inserts a revocation; RevokeCertificate calls it on its
// transaction
func (p *Provider) registerRevoked(ctx context.Context, m *model.Revoked) (*model.Revoked, error) {
	im := *m
	if im.ID.IsZero() {
		im.ID = p.NextID()
	}

	err := xdb.Validate(&im)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	q, name := query.RegisterRevoked()
	defer DbMeasureQuerySince(name, time.Now())

	res, err := xdb.QueryRow[model.Revoked](ctx, p, q,
		im.ID,
		im.OrgID,
		im.ProjectID,
		im.CertificateID,
		im.Ikid,
		im.SerialNumber,
		im.NotAfter,
		im.RevokedAt,
		im.Reason,
		im.ReasonText,
	)
	if err != nil {
		p.CheckErrIDConflict(ctx, err, im.ID.UInt64())
		return nil, err
	}
	return res, nil
}

// GetRevoked returns the revocation of a certificate by its ID, or by the
// key identifier of its issuer and its serial number
func (p *Provider) GetRevoked(ctx context.Context, req *query.GetRevokedRequest) (*model.Revoked, error) {
	err := xdb.Validate(req)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	qp := req.QueryParams()
	q, name := query.GetRevoked(qp)
	defer DbMeasureQuerySince(name, time.Now())

	res, err := xdb.QueryRow[model.Revoked](ctx, p, q, qp.Args()...)
	if err != nil {
		id := fmt.Sprintf("%s/%s", req.IKID, req.SerialNumber)
		if req.CertificateID != 0 {
			id = fmt.Sprintf("%d", req.CertificateID)
		}
		return nil, xdb.CheckNotFoundError(err, schema.RevokedTableInfo.Name, id)
	}
	return res, nil
}

// ListRevoked lists revocations, newest first; the request names its org
// scope. A CRL is built from the revocations of an issuer that are still
// valid.
func (p *Provider) ListRevoked(ctx context.Context, req *query.ListRevokedRequest) (*model.RevokedResult, error) {
	err := xdb.Validate(req)
	if err != nil {
		return nil, err
	}
	qp := req.QueryParams()
	q, name := query.ListRevoked(qp)
	defer DbMeasureQuerySince(name, time.Now())

	var rs model.RevokedResult
	err = listRows(ctx, p, req.Cursor, revokedCursor, &rs, q, qp)
	if err != nil {
		return nil, err
	}
	return &rs, nil
}

// revokedCursor returns the cursor of the page after the row
func revokedCursor(last *model.Revoked) string {
	return query.EncodeCursor(last.ID)
}

// ListRevokedCertificates lists revoked certificates with their certificate
// columns, newest revocation first; the request names its org scope
func (p *Provider) ListRevokedCertificates(ctx context.Context, req *query.ListRevokedCertificatesRequest) (*model.RevokedCertificateResult, error) {
	err := xdb.Validate(req)
	if err != nil {
		return nil, err
	}
	qp := req.QueryParams()
	q, name := query.ListRevokedCertificates(qp)
	defer DbMeasureQuerySince(name, time.Now())

	var rs model.RevokedCertificateResult
	err = listRows(ctx, p, req.Cursor, revokedCertificateCursor, &rs, q, qp)
	if err != nil {
		return nil, err
	}
	return &rs, nil
}

// revokedCertificateCursor returns the cursor of the page after the row
func revokedCertificateCursor(last *model.RevokedCertificate) string {
	return query.EncodeCursor(last.ID)
}
