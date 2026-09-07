package query

import (
	"time"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/schema"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xdb/xsql"
)

// CreateEvent returns SQL query
func CreateEvent(args ...any) (string, string) {
	const key = "CreateEvent"
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		q := schema.EventTableInfo.InsertInto().
			Returning(schema.EventTableInfo.AllColumns())
		// set all columns to nil as placeholders
		q.NewRow().
			Set(schema.Event.ID.Name, nil).
			Set(schema.Event.OrgID.Name, nil).
			Set(schema.Event.Type.Name, nil).
			Set(schema.Event.Title.Name, nil).
			Set(schema.Event.Description.Name, nil).
			Set(schema.Event.Metadata.Name, nil).
			Set(schema.Event.ReferenceID.Name, nil).
			Set(schema.Event.Email.Name, nil).
			Set(schema.Event.Source.Name, nil).
			SetExpr(schema.Event.CreatedAt.Name, "Now()")
		return q
	})
}

// ListEventsRequest defines request for Events.
// The events are sorted by created_at DESC, id DESC.
// The latest events are at the top.
type ListEventsRequest struct {
	// OrgID specifies the org
	OrgID uint64
	// After specifies the inclusive start of the created_at range
	After *time.Time
	// Before specifies the exclusive end of the created_at range
	Before *time.Time
	// Type specifies event types to query
	Type pb.EventType_Enum
	// ReferenceID specifies the referenced entity ID to filter by
	ReferenceID uint64
	// Email specifies the email to filter by
	Email string
	// Source specifies the source to filter by
	Source string
	// Limit specifies maximum number of records to return
	Limit uint32
	// Offset specifies the offset for pagination
	Offset uint32

	// TODO: not implemented yet
	// Cursor specifies the cursor for pagination
	// Cursor string
}

/*
// EncodeCursor returns the cursor for pagination
func (r *ListEventsRequest) EncodeCursor(row *model.Event) string {
	// note: uint64 shall be encoded as string
	cursor := values.MapAny{
		"id": row.ID.String(),
		"created_at": row.CreatedAt.String(),
	}
	return xdb.EncodeCursor(cursor)
}

// DecodeCursor decodes the cursor for pagination
func (r *ListEventsRequest) DecodeCursor() uint64 {
	if r.Cursor == "initial" {
		return 0
	}
	cursor, err := xdb.DecodeCursor(r.Cursor)
	if err == nil {
		return cursor.UInt64("id")
	}
	logger.KV(xlog.ERROR,
		"reason", "DecodeCursor",
		"cursor", r.Cursor,
		"err", err.Error())

	return 0
}
*/

// QueryParams returns the query params builder
func (r *ListEventsRequest) QueryParams() xdb.QueryParams {
	b := xdb.NewQueryParams("ListEvents")

	if r.OrgID > 0 {
		b.Set(schema.Event.OrgID.Position, r.OrgID)
	}
	if r.Type != pb.EventType_Unknown {
		b.Set(schema.Event.Type.Position, r.Type)
	}
	if r.After != nil {
		b.Set(62, r.After.UTC())
	}
	if r.Before != nil {
		// Use 63
		b.Set(63, r.Before.UTC())
	}
	if r.ReferenceID > 0 {
		b.Set(schema.Event.ReferenceID.Position, r.ReferenceID)
	}
	if r.Email != "" {
		b.Set(schema.Event.Email.Position, r.Email)
	}
	if r.Source != "" {
		b.Set(schema.Event.Source.Position, r.Source)
	}

	// TODO
	// if r.Cursor != "" {
	// 	cursor := r.DecodeCursor()
	// 	b.SetCursor(r.Limit, schema.Issue.ID.Position, cursor)
	// } else {

	b.SetPage(r.Limit, r.Offset)
	return b
}

// ListEvents returns SQL query
func ListEvents(args ...any) (string, string) {
	p := xdb.GetQueryParams(args...)
	key := p.Name()

	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		q := schema.EventTableInfo.Select().
			Limit(0).
			Offset(0).
			OrderBy("created_at DESC, id DESC")

		if p.IsSet(schema.Event.OrgID.Position) {
			q.Where("org_id = ?", nil)
		}
		if p.IsSet(schema.Event.Type.Position) {
			q.Where("type = ?", nil)
		}
		if p.IsSet(62) {
			q.Where("created_at >= ?", nil)
		}
		if p.IsSet(63) {
			q.Where("created_at < ?", nil)
		}
		if p.IsSet(schema.Event.ReferenceID.Position) {
			q.Where("ref_id = ?", nil)
		}
		if p.IsSet(schema.Event.Email.Position) {
			q.Where("email = ?", nil)
		}
		if p.IsSet(schema.Event.Source.Position) {
			q.Where("source = ?", nil)
		}
		return q
	})
}
