package query_test

import (
	"testing"
	"time"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/internal/db/schema"
	"github.com/effective-security/xdb"
	"github.com/stretchr/testify/require"
)

func Test_EventsQuery(t *testing.T) {
	t.Parallel()

	before := time.Now().Add(-1 * time.Hour)
	after := time.Now().Add(1 * time.Hour)
	cursor, err := query.ParseTimeCursor(query.EncodeTimeCursor(xdb.Time(before), xdb.NewID(5)))
	require.NoError(t, err)

	check(t, []tcase{
		{
			// a cursor page filters past the key of the last row
			query.ListEvents, []any{&query.ListEventsRequest{OrgID: 1, ProjectID: 2, Limit: 10, Cursor: cursor}},
			`SELECT ` + schema.EventTableInfo.AllColumns() + ` 
FROM trustyca.event 
WHERE org_id = $1 AND project_id = $2 AND (created_at, id) < ($3, $4) 
ORDER BY created_at DESC, id DESC 
LIMIT $5`,
		},
		{
			// the first page of cursor pagination is offset 0
			query.ListEvents, []any{&query.ListEventsRequest{OrgID: 1, Limit: 10, Cursor: query.NewCursor(0)}},
			`SELECT ` + schema.EventTableInfo.AllColumns() + ` 
FROM trustyca.event 
WHERE org_id = $1 
ORDER BY created_at DESC, id DESC 
LIMIT $2 
OFFSET $3`,
		},
		{
			query.CreateEvent, nil,
			`INSERT INTO trustyca.event 
( id, org_id, project_id, type, title, description, metadata, ref_id, email, source, created_at 
) VALUES ( $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, Now() 
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
