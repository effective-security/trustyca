package query_test

import (
	"testing"
	"time"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/internal/db/schema"
)

func Test_EventsQuery(t *testing.T) {
	t.Parallel()

	before := time.Now().Add(-1 * time.Hour)
	after := time.Now().Add(1 * time.Hour)

	check(t, []tcase{
		{
			query.CreateEvent, nil,
			`INSERT INTO trustyca.event 
( id, org_id, type, title, description, metadata, ref_id, email, source, created_at 
) VALUES ( $1, $2, $3, $4, $5, $6, $7, $8, $9, Now() 
) 
RETURNING ` + schema.EventTableInfo.AllColumns(),
		},
		{
			query.ListEvents, []any{&query.ListEventsRequest{OrgID: 1, Email: "a@example.com"}},
			`SELECT ` + schema.EventTableInfo.AllColumns() + ` 
FROM trustyca.event 
WHERE org_id = $1 AND email = $2 
ORDER BY created_at DESC, id DESC 
LIMIT $3 
OFFSET $4`,
		},
		{
			query.ListEvents, []any{&query.ListEventsRequest{OrgID: 1, ReferenceID: 1}},
			`SELECT ` + schema.EventTableInfo.AllColumns() + ` 
FROM trustyca.event 
WHERE org_id = $1 AND ref_id = $2 
ORDER BY created_at DESC, id DESC 
LIMIT $3 
OFFSET $4`,
		},
		{
			query.ListEvents, []any{&query.ListEventsRequest{OrgID: 1, Type: pb.EventType_OrgCreated, Source: "cli", Limit: 10, Offset: 20}},
			`SELECT ` + schema.EventTableInfo.AllColumns() + ` 
FROM trustyca.event 
WHERE org_id = $1 AND type = $2 AND source = $3 
ORDER BY created_at DESC, id DESC 
LIMIT $4 
OFFSET $5`,
		},
		{
			query.ListEvents, []any{&query.ListEventsRequest{OrgID: 1, Before: &before, After: &after}},
			`SELECT ` + schema.EventTableInfo.AllColumns() + ` 
FROM trustyca.event 
WHERE org_id = $1 AND created_at >= $2 AND created_at < $3 
ORDER BY created_at DESC, id DESC 
LIMIT $4 
OFFSET $5`,
		},
	})
}
