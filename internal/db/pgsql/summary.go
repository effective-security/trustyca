package pgsql

import (
	"context"
	"database/sql"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xlog"
)

// summarySnapshot are the options of the transaction of GetSummaryCounts:
// read-only, and REPEATABLE READ so that every statement of the summary
// sees the snapshot of the first
var summarySnapshot = &sql.TxOptions{
	Isolation: sql.LevelRepeatableRead,
	ReadOnly:  true,
}

// GetSummaryCounts reads the counts of the tenant summary at one snapshot:
// a read-only REPEATABLE READ transaction runs the issuer counts, the
// certificate counts and every page of the CRL states, so the counts agree
// with each other and with the states, as the dashboard reports them at one
// time. The transaction holds no lock and is rolled back when the reads
// are done.
func (p *Provider) GetSummaryCounts(ctx context.Context, req *query.SummaryRequest) (*model.SummaryCounts, error) {
	err := xdb.Validate(req)
	if err != nil {
		return nil, err
	}
	tx, err := p.BeginTx(ctx, summarySnapshot)
	if err != nil {
		return nil, err
	}
	defer func() {
		err := tx.Close()
		if err != nil {
			logger.ContextKV(ctx, xlog.ERROR, "reason", "close", "err", err.Error())
		}
	}()

	txProvider := tx.(*Provider)
	res := &model.SummaryCounts{}
	res.Issuers, err = txProvider.CountIssuers(ctx, req.Issuers())
	if err != nil {
		return nil, err
	}
	res.Certificates, err = txProvider.CountCertificates(ctx, req.Certificates())
	if err != nil {
		return nil, err
	}
	cursor := query.NewCursor(0)
	for {
		page, err := txProvider.ListCrlStates(ctx, req.CrlStates(cursor))
		if err != nil {
			return nil, err
		}
		res.CrlStates = append(res.CrlStates, page.Rows...)
		if !page.HasNextPage {
			break
		}
		cursor, err = query.ParseCursor(page.Cursor)
		if err != nil {
			return nil, errors.WithStack(err)
		}
	}
	return res, nil
}
