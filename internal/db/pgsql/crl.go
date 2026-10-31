package pgsql

import (
	"context"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/internal/db/schema"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xlog"
	"github.com/lib/pq"
)

// ErrStaleCrlNumber is returned by PublishCrl when the CRL number is not
// greater than the issuer's current one: another publisher won, and the
// caller signs a new CRL with the next number
var ErrStaleCrlNumber = errors.New("crl number is not greater than the issuer's crl number")

// PublishCrl stores the current CRL of an issuer and records its number on
// the issuer in one transaction. The CRL's IKID must be the issuer's SKID
// and the number greater than the issuer's current CRL number, so the number
// of an IKID only grows: otherwise nothing is stored and ErrStaleCrlNumber
// is returned. The tenancy and issuer name of the CRL are copied from the
// issuer row.
func (p *Provider) PublishCrl(ctx context.Context, m *model.Crl) (*model.Crl, error) {
	im := *m
	if im.ID.IsZero() {
		im.ID = p.NextID()
	}
	if im.IssuerID.IsZero() {
		return nil, errors.New("invalid issuer ID")
	}
	if im.Ikid == "" {
		return nil, errors.New("invalid ikid: required")
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
	issuer, err := txProvider.setIssuerCrlNumber(ctx, im.IssuerID, im.Ikid, im.CrlNumber)
	if err != nil {
		return nil, err
	}
	im.OrgID = issuer.OrgID
	im.ProjectID = issuer.ProjectID
	im.Issuer = issuer.Subject

	err = xdb.Validate(&im)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	q, name := query.PublishCrl()
	defer DbMeasureQuerySince(name, time.Now())

	res, err := xdb.QueryRow[model.Crl](ctx, txProvider, q,
		im.ID,
		im.OrgID,
		im.ProjectID,
		im.IssuerID,
		im.Ikid,
		im.CrlNumber,
		im.ThisUpdate,
		im.NextUpdate,
		im.Issuer,
		im.Pem,
		query.LocationsArg(im.Locations),
	)
	if err != nil {
		p.CheckErrIDConflict(ctx, err, im.ID.UInt64())
		return nil, errors.WithMessage(err, "unable to store crl")
	}

	err = tx.Commit()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return res, nil
}

// setIssuerCrlNumber records the number of a published CRL on the issuer
// with the ID and the SKID, and returns the issuer; the number must be
// greater than the current one
func (p *Provider) setIssuerCrlNumber(ctx context.Context, issuerID xdb.ID, ikid string, number int64) (*model.Issuer, error) {
	q, name := query.SetIssuerCrlNumber()
	defer DbMeasureQuerySince(name, time.Now())

	res, err := xdb.QueryRow[model.Issuer](ctx, p, q, number, issuerID, ikid, number)
	if err == nil {
		return res, nil
	}
	if !xdb.IsNotFoundError(err) {
		return nil, errors.WithMessage(err, "unable to update issuer crl number")
	}
	// no row was updated: the issuer does not exist, the IKID is another
	// issuer's, or the number is not greater
	issuer, err := p.GetIssuer(ctx, issuerID.UInt64())
	if err != nil {
		return nil, err
	}
	if issuer.Skid != ikid {
		return nil, errors.Errorf("crl ikid %s does not match issuer %s", ikid, issuerID.String())
	}
	return nil, errors.WithStack(ErrStaleCrlNumber)
}

// GetCrl returns the current CRL of the issuer with the key identifier
func (p *Provider) GetCrl(ctx context.Context, ikid string) (*model.Crl, error) {
	q, name := query.GetCrlByIKID()
	defer DbMeasureQuerySince(name, time.Now())

	res, err := xdb.QueryRow[model.Crl](ctx, p, q, ikid)
	if err != nil {
		return nil, xdb.CheckNotFoundError(err, schema.CrlTableInfo.Name, ikid)
	}
	return res, nil
}

// GetCrls returns the current CRLs of the issuers with the key identifiers,
// in any order; an issuer without a CRL has none in the result. The CRL
// publisher reads the CRLs of a page of issuers in one query, so the list
// is bounded by the caller's page; no key identifiers read nothing.
func (p *Provider) GetCrls(ctx context.Context, ikids []string) ([]*model.Crl, error) {
	if len(ikids) == 0 {
		return nil, nil
	}
	q, name := query.GetCrlsByIKIDs()
	defer DbMeasureQuerySince(name, time.Now())

	res, err := xdb.ExecuteListQuery[model.Crl](ctx, p, q, pq.Array(ikids))
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return res, nil
}

// ListCrls lists the current CRLs, newest first; the request names its org
// scope
func (p *Provider) ListCrls(ctx context.Context, req *query.ListCrlsRequest) (*model.CrlResult, error) {
	err := xdb.Validate(req)
	if err != nil {
		return nil, err
	}
	qp := req.QueryParams()
	q, name := query.ListCrls(qp)
	defer DbMeasureQuerySince(name, time.Now())

	var rs model.CrlResult
	err = listRows(ctx, p, req.Cursor, crlCursor, &rs, q, qp)
	if err != nil {
		return nil, err
	}
	return &rs, nil
}

// crlCursor returns the cursor of the page after the row
func crlCursor(last *model.Crl) string {
	return query.EncodeCursor(last.ID)
}

// ListCrlStates lists the issuers of the org of the request with the
// lifecycle statuses of the request, newest first, with the state of their
// current CRL: the columns the tenant summary classifies, never a PEM
func (p *Provider) ListCrlStates(ctx context.Context, req *query.ListCrlStatesRequest) (*model.CrlStateResult, error) {
	err := xdb.Validate(req)
	if err != nil {
		return nil, err
	}
	qp := req.QueryParams()
	q, name := query.ListCrlStates(qp)
	defer DbMeasureQuerySince(name, time.Now())

	var rs model.CrlStateResult
	err = listRows(ctx, p, req.Cursor, crlStateCursor, &rs, q, qp)
	if err != nil {
		return nil, err
	}
	return &rs, nil
}

// crlStateCursor returns the cursor of the page after the row
func crlStateCursor(last *model.CrlState) string {
	return query.EncodeCursor(last.ID)
}

// DeleteCrl deletes the current CRL of the issuer with the key identifier in
// the exact org scope (a zero orgID is the platform) and returns the number
// of deleted rows
func (p *Provider) DeleteCrl(ctx context.Context, orgID uint64, ikid string) (int64, error) {
	q, name := query.DeleteCrl()
	defer DbMeasureQuerySince(name, time.Now())

	res, err := p.ExecContext(ctx, q, query.OrgArg(orgID), ikid)
	if err != nil {
		return 0, errors.WithStack(err)
	}
	return res.RowsAffected()
}
