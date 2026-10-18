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
)

// RegisterIssuer inserts an issuer. A Pending issuer carries its CSR, any
// other status its certificate; the label is unique in its scope and the
// SKID across the table.
func (p *Provider) RegisterIssuer(ctx context.Context, m *model.Issuer) (*model.Issuer, error) {
	im := *m
	if im.ID.IsZero() {
		im.ID = p.NextID()
	}

	err := xdb.Validate(&im)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	q, name := query.RegisterIssuer()
	defer DbMeasureQuerySince(name, time.Now())

	res, err := xdb.QueryRow[model.Issuer](ctx, p, q,
		im.ID,
		im.OrgID,
		im.ProjectID,
		im.Label,
		im.Type,
		im.Status,
		im.ParentID,
		im.Skid,
		im.Ikid,
		im.SerialNumber,
		im.Subject,
		im.Issuer,
		im.Sha256,
		im.NotBefore,
		im.NotAfter,
		im.Pem,
		im.ChainPem,
		im.RootPem,
		im.CsrPem,
		im.KeyProvider,
		im.KeyID,
		im.KeyProtected,
		im.Config,
		im.CrlNumber,
	)
	if err != nil {
		p.CheckErrIDConflict(ctx, err, im.ID.UInt64())
		return nil, err
	}
	return res, nil
}

// UpdateIssuer changes the lifecycle status or the runtime settings of an
// issuer of the exact org scope; the Destroyed status also clears the
// protected key material. The config must be a pb.IssuerConfig document.
func (p *Provider) UpdateIssuer(ctx context.Context, req *query.UpdateIssuerRequest) (*model.Issuer, error) {
	if req.ID == 0 {
		return nil, errors.New("issuer ID is required")
	}
	if req.Status == pb.IssuerStatus_Unknown && len(req.Config) == 0 {
		return nil, errors.New("no changes to update")
	}
	if len(req.Config) > 0 {
		// an unreadable config would fail every later read of the issuer
		err := pb.JsonUnmarshalOptions.Unmarshal(req.Config, new(pb.IssuerConfig))
		if err != nil {
			return nil, errors.WithMessage(err, "invalid config")
		}
	}

	qp := req.QueryParams()
	q, name := query.UpdateIssuer(qp)
	defer DbMeasureQuerySince(name, time.Now())

	res, err := xdb.QueryRow[model.Issuer](ctx, p, q, qp.Args()...)
	if err != nil {
		return nil, xdb.CheckNotFoundError(err, schema.IssuerTableInfo.Name, req.ID)
	}
	return res, nil
}

// ActivateIssuer sets the certificate columns of a Pending issuer from the
// model, clears its CSR and makes it Active. The issuer is reported as not
// found when it does not exist, is not Pending or is not of the model's org.
func (p *Provider) ActivateIssuer(ctx context.Context, m *model.Issuer) (*model.Issuer, error) {
	if m.ID.IsZero() {
		return nil, errors.New("issuer ID is required")
	}
	im := *m
	im.Status = pb.IssuerStatus_Active
	im.CsrPem = ""

	err := xdb.Validate(&im)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	q, name := query.ActivateIssuer()
	defer DbMeasureQuerySince(name, time.Now())

	res, err := xdb.QueryRow[model.Issuer](ctx, p, q,
		im.Skid,
		im.Ikid,
		im.SerialNumber,
		im.Subject,
		im.Issuer,
		im.Sha256,
		im.NotBefore,
		im.NotAfter,
		im.Pem,
		im.ChainPem,
		im.RootPem,
		pb.IssuerStatus_Active,
		im.ID,
		pb.IssuerStatus_Pending,
		im.OrgID,
	)
	if err != nil {
		return nil, xdb.CheckNotFoundError(err, schema.IssuerTableInfo.Name, im.ID)
	}
	return res, nil
}

// GetIssuer returns an issuer by ID
func (p *Provider) GetIssuer(ctx context.Context, id uint64) (*model.Issuer, error) {
	q, name := query.GetRowByID(&schema.IssuerTableInfo)
	defer DbMeasureQuerySince(name, time.Now())

	res, err := xdb.QueryRow[model.Issuer](ctx, p, q, id)
	if err != nil {
		return nil, xdb.CheckNotFoundError(err, schema.IssuerTableInfo.Name, id)
	}
	return res, nil
}

// FindIssuer returns the issuer of the exact scope and label: a zero orgID
// is the platform scope and a zero projectID the org scope. The resolution
// of a label through the scopes is the caller's.
func (p *Provider) FindIssuer(ctx context.Context, orgID, projectID uint64, label string) (*model.Issuer, error) {
	req := &query.FindIssuerRequest{
		OrgID:     orgID,
		ProjectID: projectID,
		Label:     label,
	}
	qp := req.QueryParams()
	q, name := query.FindIssuer(qp)
	defer DbMeasureQuerySince(name, time.Now())

	res, err := xdb.QueryRow[model.Issuer](ctx, p, q, qp.Args()...)
	if err != nil {
		return nil, xdb.CheckNotFoundError(err, schema.IssuerTableInfo.Name, fmt.Sprintf("%d/%d/%s", orgID, projectID, label))
	}
	return res, nil
}

// GetIssuerBySKID returns the issuer by its Subject Key Identifier, which is
// the IKID of the certificates and CRLs it issued
func (p *Provider) GetIssuerBySKID(ctx context.Context, skid string) (*model.Issuer, error) {
	q, name := query.GetIssuerBySKID()
	defer DbMeasureQuerySince(name, time.Now())

	res, err := xdb.QueryRow[model.Issuer](ctx, p, q, skid)
	if err != nil {
		return nil, xdb.CheckNotFoundError(err, schema.IssuerTableInfo.Name, skid)
	}
	return res, nil
}

// ListIssuers lists issuers, newest first; the request names its org scope
func (p *Provider) ListIssuers(ctx context.Context, req *query.ListIssuersRequest) (*model.IssuerResult, error) {
	err := xdb.Validate(req)
	if err != nil {
		return nil, err
	}
	qp := req.QueryParams()
	q, name := query.ListIssuers(qp)
	defer DbMeasureQuerySince(name, time.Now())

	var rs model.IssuerResult
	err = listRows(ctx, p, req.Cursor, issuerCursor, &rs, q, qp)
	if err != nil {
		return nil, err
	}
	return &rs, nil
}

// issuerCursor returns the cursor of the page after the row
func issuerCursor(last *model.Issuer) string {
	return query.EncodeCursor(last.ID)
}

// DeleteIssuer deletes an issuer of the exact org scope (a zero orgID is the
// platform) and its current CRL, and returns the number of deleted issuers.
// The certificates it issued are kept: the lifecycle of an issuer ends with
// the Destroyed status, deletion is for operators.
func (p *Provider) DeleteIssuer(ctx context.Context, orgID, id uint64) (int64, error) {
	q, name := query.DeleteRowByOrgAndID(&schema.IssuerTableInfo)
	defer DbMeasureQuerySince(name, time.Now())

	res, err := p.ExecContext(ctx, q, query.OrgArg(orgID), id)
	if err != nil {
		return 0, errors.WithStack(err)
	}
	return res.RowsAffected()
}
