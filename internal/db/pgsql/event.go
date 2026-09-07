package pgsql

import (
	"context"
	"time"

	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/internal/db/schema"
	"github.com/effective-security/x/slices"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xlog"
)

func (p *Provider) TryCreateEvent(evt *model.Event) {
	go func(evt *model.Event) {
		_, err := p.CreateEvent(context.Background(), evt)
		if err != nil {
			logger.KV(xlog.ERROR,
				"reason", "CreateEvent",
				"org_id", evt.OrgID.UnderscoreString(),
				"type", evt.Type,
				"err", err.Error())
		}
	}(evt)
}

// CreateEvent returns new Event
func (p *Provider) CreateEvent(ctx context.Context, m *model.Event) (*model.Event, error) {
	err := xdb.Validate(m)
	if err != nil {
		return nil, err
	}

	q, name := query.CreateEvent()
	defer DbMeasureQuerySince(name, time.Now())

	id := p.NextID()
	res, err := xdb.QueryRow[model.Event](ctx, p,
		q,
		id.UInt64(),
		m.OrgID.UInt64(),
		m.Type,
		slices.StringUpto(m.Title, 254),
		m.Description,
		m.Metadata,
		m.ReferenceID.UInt64(),
		m.Email,
		m.Source,
	)
	if err != nil {
		p.CheckErrIDConflict(ctx, err, id.UInt64())
		return nil, err
	}

	return res, nil
}

// ListEvents returns events
func (p *Provider) ListEvents(ctx context.Context, r *query.ListEventsRequest) (*model.EventResult, error) {
	qp := r.QueryParams()
	q, name := query.ListEvents(qp)
	defer DbMeasureQuerySince(name, time.Now())

	var rs model.EventResult
	err := xdb.ExecuteQueryWithPagination(ctx, p, &rs, q, qp)
	if err != nil {
		return nil, err
	}
	return &rs, nil
}

// GetEvent returns Event
func (p *Provider) GetEvent(ctx context.Context, id uint64) (*model.Event, error) {
	q, name := query.GetRowByID(&schema.EventTableInfo)
	defer DbMeasureQuerySince(name, time.Now())

	res, err := xdb.QueryRow[model.Event](ctx, p, q, id)
	if err != nil {
		return nil, xdb.CheckNotFoundError(err, schema.EventTableInfo.Name, id)
	}

	return res, nil
}
