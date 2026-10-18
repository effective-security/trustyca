package pgsql

import (
	"context"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/internal/db/schema"
	"github.com/effective-security/xdb"
)

// ErrRootConflict is returned by RegisterRoot when the certificate is
// registered in another scope: the thumbprint is unique across the table
var ErrRootConflict = errors.New("root certificate is registered in another scope")

// RegisterRoot registers a trust anchor. Registering the same certificate
// again in the same scope updates its trust and returns the existing row;
// the same certificate in another scope fails with ErrRootConflict.
func (p *Provider) RegisterRoot(ctx context.Context, m *model.RootCertificate) (*model.RootCertificate, error) {
	im := *m
	if im.ID.IsZero() {
		im.ID = p.NextID()
	}

	err := xdb.Validate(&im)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	q, name := query.RegisterRoot()
	defer DbMeasureQuerySince(name, time.Now())

	res, err := xdb.QueryRow[model.RootCertificate](ctx, p, q,
		im.ID,
		im.OrgID,
		im.Skid,
		im.NotBefore,
		im.NotAfter,
		im.Subject,
		im.Sha256,
		im.Trust,
		im.Pem,
	)
	if err != nil {
		if xdb.IsNotFoundError(err) {
			// the conflicting row belongs to another scope, so the
			// conditional update returned no row
			return nil, errors.WithStack(ErrRootConflict)
		}
		p.CheckErrIDConflict(ctx, err, im.ID.UInt64())
		return nil, err
	}
	return res, nil
}

// GetRoot returns a trust anchor by ID
func (p *Provider) GetRoot(ctx context.Context, id uint64) (*model.RootCertificate, error) {
	q, name := query.GetRowByID(&schema.RootCertificateTableInfo)
	defer DbMeasureQuerySince(name, time.Now())

	res, err := xdb.QueryRow[model.RootCertificate](ctx, p, q, id)
	if err != nil {
		return nil, xdb.CheckNotFoundError(err, schema.RootCertificateTableInfo.Name, id)
	}
	return res, nil
}

// ListRoots lists trust anchors, newest first; the request names its org
// scope
func (p *Provider) ListRoots(ctx context.Context, req *query.ListRootsRequest) (*model.RootCertificateResult, error) {
	err := xdb.Validate(req)
	if err != nil {
		return nil, err
	}
	qp := req.QueryParams()
	q, name := query.ListRoots(qp)
	defer DbMeasureQuerySince(name, time.Now())

	var rs model.RootCertificateResult
	err = listRows(ctx, p, req.Cursor, rootCursor, &rs, q, qp)
	if err != nil {
		return nil, err
	}
	return &rs, nil
}

// rootCursor returns the cursor of the page after the row
func rootCursor(last *model.RootCertificate) string {
	return query.EncodeCursor(last.ID)
}

// DeleteRoot deletes a trust anchor of the exact org scope (a zero orgID is
// the platform) and returns the number of deleted rows
func (p *Provider) DeleteRoot(ctx context.Context, orgID, id uint64) (int64, error) {
	q, name := query.DeleteRowByOrgAndID(&schema.RootCertificateTableInfo)
	defer DbMeasureQuerySince(name, time.Now())

	res, err := p.ExecContext(ctx, q, query.OrgArg(orgID), id)
	if err != nil {
		return 0, errors.WithStack(err)
	}
	return res.RowsAffected()
}
