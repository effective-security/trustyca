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

// RegisterCertificate inserts the issuance record of a certificate; the
// status defaults to Active. The thumbprint and the issuer and serial number
// pair are unique. With an event, the insert and the event are one
// transaction, and the event references the certificate when it has no
// reference of its own.
func (p *Provider) RegisterCertificate(ctx context.Context, m *model.Certificate, evt *model.Event) (*model.Certificate, error) {
	im := *m
	if im.ID.IsZero() {
		im.ID = p.NextID()
	}
	if im.Status == pb.CertificateStatus_Unknown {
		im.Status = pb.CertificateStatus_Active
	}

	err := xdb.Validate(&im)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if evt == nil {
		return p.registerCertificate(ctx, &im)
	}
	err = xdb.Validate(evt)
	if err != nil {
		return nil, errors.WithStack(err)
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
	res, err := txProvider.registerCertificate(ctx, &im)
	if err != nil {
		return nil, err
	}

	e := *evt
	if e.ReferenceID.IsZero() {
		e.ReferenceID = res.ID
	}
	_, err = txProvider.CreateEvent(ctx, &e)
	if err != nil {
		return nil, errors.WithMessage(err, "unable to record event")
	}

	err = tx.Commit()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return res, nil
}

// registerCertificate inserts the validated certificate on the receiver,
// which is the transaction of RegisterCertificate when it records an event
func (p *Provider) registerCertificate(ctx context.Context, im *model.Certificate) (*model.Certificate, error) {
	q, name := query.RegisterCertificate()
	defer DbMeasureQuerySince(name, time.Now())

	res, err := xdb.QueryRow[model.Certificate](ctx, p, q,
		im.ID,
		im.OrgID,
		im.ProjectID,
		im.Skid,
		im.Ikid,
		im.SerialNumber,
		im.NotBefore,
		im.NotAfter,
		im.Subject,
		im.Issuer,
		im.Sha256,
		im.Profile,
		im.Label,
		query.LocationsArg(im.Locations),
		query.MetadataArg(im.Metadata),
		im.Pem,
		im.IssuersPem,
		im.Status,
	)
	if err != nil {
		p.CheckErrIDConflict(ctx, err, im.ID.UInt64())
		return nil, err
	}
	return res, nil
}

// UpdateCertificate replaces the label, the client metadata or the published
// locations of a certificate of the exact org scope
func (p *Provider) UpdateCertificate(ctx context.Context, req *query.UpdateCertificateRequest) (*model.Certificate, error) {
	if req.ID == 0 {
		return nil, errors.New("certificate ID is required")
	}
	if req.Label == nil && req.Metadata == nil && req.Locations == nil {
		return nil, errors.New("no changes to update")
	}
	if req.Label != nil && len(*req.Label) > model.MaxLenForName {
		return nil, errors.Errorf("invalid label length: %d", len(*req.Label))
	}
	for _, loc := range req.Locations {
		if loc == "" || len(loc) > model.MaxLenForName {
			return nil, errors.Errorf("invalid location length: %d", len(loc))
		}
	}

	qp := req.QueryParams()
	q, name := query.UpdateCertificate(qp)
	defer DbMeasureQuerySince(name, time.Now())

	res, err := xdb.QueryRow[model.Certificate](ctx, p, q, qp.Args()...)
	if err != nil {
		return nil, xdb.CheckNotFoundError(err, schema.CertificateTableInfo.Name, req.ID)
	}
	return res, nil
}

// updateCertificateStatus sets the status of a certificate; RevokeCertificate
// calls it on its transaction
func (p *Provider) updateCertificateStatus(ctx context.Context, id xdb.ID, status pb.CertificateStatus_Enum) (*model.Certificate, error) {
	q, name := query.UpdateCertificateStatus()
	defer DbMeasureQuerySince(name, time.Now())

	res, err := xdb.QueryRow[model.Certificate](ctx, p, q, status, id)
	if err != nil {
		return nil, xdb.CheckNotFoundError(err, schema.CertificateTableInfo.Name, id)
	}
	return res, nil
}

// getCertificateForUpdate returns a certificate by ID and exact org scope,
// and locks its row for the rest of the transaction
func (p *Provider) getCertificateForUpdate(ctx context.Context, id uint64, orgID xdb.ID) (*model.Certificate, error) {
	q, name := query.GetCertificateForUpdate()
	defer DbMeasureQuerySince(name, time.Now())

	res, err := xdb.QueryRow[model.Certificate](ctx, p, q, id, orgID)
	if err != nil {
		return nil, xdb.CheckNotFoundError(err, schema.CertificateTableInfo.Name, id)
	}
	return res, nil
}

// GetCertificate returns a certificate by ID
func (p *Provider) GetCertificate(ctx context.Context, id uint64) (*model.Certificate, error) {
	q, name := query.GetRowByID(&schema.CertificateTableInfo)
	defer DbMeasureQuerySince(name, time.Now())

	res, err := xdb.QueryRow[model.Certificate](ctx, p, q, id)
	if err != nil {
		return nil, xdb.CheckNotFoundError(err, schema.CertificateTableInfo.Name, id)
	}
	return res, nil
}

// GetCertificateBySha256 returns a certificate by its hex encoded SHA-256
// thumbprint
func (p *Provider) GetCertificateBySha256(ctx context.Context, sha256 string) (*model.Certificate, error) {
	q, name := query.GetCertificateBySha256()
	defer DbMeasureQuerySince(name, time.Now())

	res, err := xdb.QueryRow[model.Certificate](ctx, p, q, sha256)
	if err != nil {
		return nil, xdb.CheckNotFoundError(err, schema.CertificateTableInfo.Name, sha256)
	}
	return res, nil
}

// GetCertificateByIssuerSerial returns a certificate by the key identifier
// of its issuer and its serial number
func (p *Provider) GetCertificateByIssuerSerial(ctx context.Context, ikid, serial string) (*model.Certificate, error) {
	q, name := query.GetCertificateByIssuerSerial()
	defer DbMeasureQuerySince(name, time.Now())

	res, err := xdb.QueryRow[model.Certificate](ctx, p, q, ikid, serial)
	if err != nil {
		return nil, xdb.CheckNotFoundError(err, schema.CertificateTableInfo.Name, fmt.Sprintf("%s/%s", ikid, serial))
	}
	return res, nil
}

// ListCertificates lists certificates, newest first; the request names its
// org scope
func (p *Provider) ListCertificates(ctx context.Context, req *query.ListCertificatesRequest) (*model.CertificateResult, error) {
	err := xdb.Validate(req)
	if err != nil {
		return nil, err
	}
	qp := req.QueryParams()
	q, name := query.ListCertificates(qp)
	defer DbMeasureQuerySince(name, time.Now())

	var rs model.CertificateResult
	err = listRows(ctx, p, req.Cursor, certificateCursor, &rs, q, qp)
	if err != nil {
		return nil, err
	}
	return &rs, nil
}

// certificateCursor returns the cursor of the page after the row
func certificateCursor(last *model.Certificate) string {
	return query.EncodeCursor(last.ID)
}

// DeleteCertificate deletes a certificate of the exact org scope (a zero
// orgID is the platform) and its revocation, and returns the number of
// deleted certificates. Certificates are audit records: the retention task
// and operators delete them, the tenant lifecycle does not.
func (p *Provider) DeleteCertificate(ctx context.Context, orgID, id uint64) (int64, error) {
	q, name := query.DeleteRowByOrgAndID(&schema.CertificateTableInfo)
	defer DbMeasureQuerySince(name, time.Now())

	res, err := p.ExecContext(ctx, q, query.OrgArg(orgID), id)
	if err != nil {
		return 0, errors.WithStack(err)
	}
	return res.RowsAffected()
}
