package pgsql

import (
	"context"
	"fmt"
	"time"

	"github.com/cockroachdb/errors"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/xdb"
)

// RegisterAPIKey inserts a new API key; the key and the protected secret are
// prepared by the caller
func (p *Provider) RegisterAPIKey(ctx context.Context, m *model.APIKey) (*model.APIKey, error) {
	im := *m
	if im.ID.UInt64() == 0 {
		im.ID = p.NextID()
	}
	if im.Status == pb.ItemStatus_Unknown {
		im.Status = pb.ItemStatus_Active
	}

	err := xdb.Validate(&im)
	if err != nil {
		return nil, err
	}

	q, name := query.RegisterAPIKey()
	defer DbMeasureQuerySince(name, time.Now())

	res, err := xdb.QueryRow[model.APIKey](ctx, p, q,
		im.ID,
		im.OrgID,
		im.ProjectID,
		im.Key,
		im.Secret,
		im.Label,
		im.Scopes,
		im.Metadata,
		im.Status,
		im.ExpiresAt,
	)
	if err != nil {
		p.CheckErrIDConflict(ctx, err, im.ID.UInt64())
		return nil, err
	}

	return res, nil
}

// ListAPIKeys lists API keys of an org
func (p *Provider) ListAPIKeys(ctx context.Context, r *query.ListAPIKeysRequest) (*model.APIKeyResult, error) {
	qp := r.QueryParams()
	q, name := query.ListAPIKeys(qp)
	defer DbMeasureQuerySince(name, time.Now())

	var rs model.APIKeyResult
	err := xdb.ExecuteQueryWithPagination(ctx, p, &rs, q, qp)
	if err != nil {
		return nil, err
	}
	return &rs, nil
}

// GetAPIKey returns an API key of the org by ID
func (p *Provider) GetAPIKey(ctx context.Context, orgID, id uint64) (*model.APIKey, error) {
	q, qn := query.GetAPIKey()
	defer DbMeasureQuerySince(qn, time.Now())

	res, err := xdb.QueryRow[model.APIKey](ctx, p, q, orgID, id)
	if err != nil {
		return nil, xdb.CheckNotFoundError(err, "api key", fmt.Sprintf("%d/%d", orgID, id))
	}

	return res, nil
}

// DeleteAPIKey deletes an API key of the org and returns the number of
// deleted rows
func (p *Provider) DeleteAPIKey(ctx context.Context, orgID, id uint64) (int64, error) {
	q, qn := query.DeleteAPIKey()
	defer DbMeasureQuerySince(qn, time.Now())

	res, err := p.ExecContext(ctx, q, orgID, id)
	if err != nil {
		return 0, errors.WithStack(err)
	}
	return res.RowsAffected()
}

// UseAPIKey increments the used count and sets the used at time
func (p *Provider) UseAPIKey(ctx context.Context, orgID, id uint64) (*model.APIKey, error) {
	q, qn := query.UseAPIKey()
	defer DbMeasureQuerySince(qn, time.Now())

	res, err := xdb.QueryRow[model.APIKey](ctx, p, q, orgID, id)
	if err != nil {
		return nil, xdb.CheckNotFoundError(err, "api key", fmt.Sprintf("%d/%d", orgID, id))
	}

	return res, nil
}
