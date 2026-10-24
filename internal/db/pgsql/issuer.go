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
	"github.com/effective-security/xpki/certutil"
)

// RegisterIssuer inserts an issuer. A Pending issuer carries its CSR, any
// other status its certificate; the label is unique in its scope and the
// SKID across the table. A root issuer requires its anchor, its own
// certificate as a trust anchor of its org, which is registered as
// RegisterRoot does in the transaction of the insert, so a root issuer is
// never stored without it; any other issuer takes none. An anchor
// registered in another scope fails both with ErrRootConflict.
func (p *Provider) RegisterIssuer(ctx context.Context, m *model.Issuer, anchor *model.RootCertificate) (*model.Issuer, error) {
	im := *m
	if im.ID.IsZero() {
		im.ID = p.NextID()
	}

	err := xdb.Validate(&im)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	isRoot := im.Type == pb.AuthorityType_Root
	switch {
	case !isRoot && anchor == nil:
		return p.registerIssuer(ctx, &im)
	case !isRoot:
		return nil, errors.New("only a root issuer has an anchor")
	case anchor == nil:
		return nil, errors.New("a root issuer requires its anchor")
	}
	err = checkAnchor(&im, anchor)
	if err != nil {
		return nil, err
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
	res, err := txProvider.registerIssuer(ctx, &im)
	if err != nil {
		return nil, err
	}
	_, err = txProvider.RegisterRoot(ctx, anchor)
	if err != nil {
		return nil, errors.WithMessage(err, "unable to register root")
	}

	err = tx.Commit()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return res, nil
}

// checkAnchor verifies that anchor is the certificate of the root issuer im
// in its org. The identity columns of the anchor are set by the caller, so
// they are compared with the ones its PEM derives, and the certificate of
// the PEM with the issuer's.
func checkAnchor(im *model.Issuer, anchor *model.RootCertificate) error {
	crt, err := certutil.ParseFromPEM([]byte(anchor.Pem))
	if err != nil {
		return errors.WithMessage(err, "invalid anchor certificate")
	}
	want := model.NewRootCertificate(crt, im.OrgID, anchor.Trust, anchor.Pem)
	same := want.Sha256 == im.Sha256 &&
		want.Skid == im.Skid &&
		anchor.OrgID.UInt64() == want.OrgID.UInt64() &&
		anchor.Sha256 == want.Sha256 &&
		anchor.Skid == want.Skid &&
		anchor.Subject == want.Subject &&
		anchor.NotBefore.UTC().Equal(want.NotBefore.UTC()) &&
		anchor.NotAfter.UTC().Equal(want.NotAfter.UTC())
	if !same {
		return errors.New("the anchor must be the certificate of the issuer in its org")
	}
	return nil
}

// registerIssuer inserts the validated issuer row
func (p *Provider) registerIssuer(ctx context.Context, im *model.Issuer) (*model.Issuer, error) {
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
