package pgsql_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/xdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Event(t *testing.T) {
	owner, org := setupOwnerAndOrg(t, "Test_Event")

	const total = 50
	created := make(model.EventSlice, 0, total)
	for i := 0; i < total; i++ {
		em := &model.Event{
			OrgID:       org.ID,
			Type:        pb.EventType_Enum(i%5 + 1),
			Title:       fmt.Sprintf("Test Event %d", i),
			Description: "This is a test event",
			Email:       xdb.NULLString(owner.Email),
			Source:      xdb.NULLString(fmt.Sprintf("test-%d", i)),
			Metadata:    map[string]string{"key": "test"},
			ReferenceID: xdb.NewID(uint64(i + 1)),
		}

		event, err := provider.CreateEvent(ctx, em)
		require.NoError(t, err)
		assert.Equal(t, em.OrgID.UInt64(), event.OrgID.UInt64())
		assert.Equal(t, em.Type, event.Type)
		assert.Equal(t, em.Title, event.Title)
		assert.Equal(t, em.Description, event.Description)
		assert.Equal(t, em.Email, event.Email)
		assert.Equal(t, em.Source, event.Source)
		assert.Equal(t, em.ReferenceID.UInt64(), event.ReferenceID.UInt64())
		assert.Equal(t, em.Metadata, event.Metadata)

		created = append(created, event)

		// spread created_at so time-range filters have distinct buckets
		if i%5 == 4 {
			time.Sleep(10 * time.Millisecond)
		}
	}

	newestFirst := reverseEvents(created)

	got, err := provider.GetEvent(ctx, created[0].ID.UInt64())
	require.NoError(t, err)
	assert.Equal(t, created[0].ID, got.ID)

	_, err = provider.GetEvent(ctx, 123)
	assert.ErrorContains(t, err, "record not found")

	t.Run("newest_to_oldest", func(t *testing.T) {
		res, err := provider.ListEvents(ctx, &query.ListEventsRequest{
			OrgID: org.ID.UInt64(),
			Limit: uint32(total + 1),
		})
		require.NoError(t, err)
		require.Len(t, res.Rows, total)
		assert.False(t, res.HasNextPage)
		assert.Equal(t, eventIDs(newestFirst), eventIDs(res.Rows))
		requireNewestFirst(t, res.Rows)
	})

	t.Run("pagination", func(t *testing.T) {
		const pageSize = uint32(10)
		first, err := provider.ListEvents(ctx, &query.ListEventsRequest{
			OrgID: org.ID.UInt64(),
			Limit: pageSize,
		})
		require.NoError(t, err)
		require.Len(t, first.Rows, int(pageSize))
		assert.True(t, first.HasNextPage)
		assert.Equal(t, pageSize, first.NextOffset)
		assert.Equal(t, eventIDs(newestFirst[:pageSize]), eventIDs(first.Rows))
		requireNewestFirst(t, first.Rows)

		second, err := provider.ListEvents(ctx, &query.ListEventsRequest{
			OrgID:  org.ID.UInt64(),
			Limit:  pageSize,
			Offset: first.NextOffset,
		})
		require.NoError(t, err)
		require.Len(t, second.Rows, int(pageSize))
		assert.True(t, second.HasNextPage)
		assert.Equal(t, uint32(20), second.NextOffset)
		assert.Equal(t, eventIDs(newestFirst[10:20]), eventIDs(second.Rows))
		requireNewestFirst(t, second.Rows)

		var loaded model.EventSlice
		req := &query.ListEventsRequest{
			OrgID: org.ID.UInt64(),
			Limit: pageSize,
		}
		for pages := 0; pages < 10; pages++ {
			rs, err := provider.ListEvents(ctx, req)
			require.NoError(t, err)
			loaded = append(loaded, rs.Rows...)
			if !rs.HasNextPage {
				break
			}
			req.Offset = rs.NextOffset
		}
		assert.Equal(t, eventIDs(newestFirst), eventIDs(loaded))
		requireNewestFirst(t, loaded)
	})

	t.Run("filter_type", func(t *testing.T) {
		expected := filterEvents(newestFirst, func(e *model.Event) bool {
			return e.Type == pb.EventType_OrgCreated
		})
		res, err := provider.ListEvents(ctx, &query.ListEventsRequest{
			OrgID: org.ID.UInt64(),
			Type:  pb.EventType_OrgCreated,
		})
		require.NoError(t, err)
		require.Len(t, res.Rows, 10)
		assert.Equal(t, eventIDs(expected), eventIDs(res.Rows))
		for _, event := range res.Rows {
			assert.Equal(t, pb.EventType_OrgCreated, event.Type)
		}
		requireNewestFirst(t, res.Rows)
	})

	t.Run("filter_email", func(t *testing.T) {
		res, err := provider.ListEvents(ctx, &query.ListEventsRequest{
			OrgID: org.ID.UInt64(),
			Email: owner.Email,
		})
		require.NoError(t, err)
		assert.Equal(t, eventIDs(newestFirst), eventIDs(res.Rows))

		empty, err := provider.ListEvents(ctx, &query.ListEventsRequest{
			OrgID: org.ID.UInt64(),
			Email: "missing@example.com",
		})
		require.NoError(t, err)
		assert.Empty(t, empty.Rows)
	})

	t.Run("filter_source", func(t *testing.T) {
		want := created[7]
		res, err := provider.ListEvents(ctx, &query.ListEventsRequest{
			OrgID:  org.ID.UInt64(),
			Source: want.Source.String(),
		})
		require.NoError(t, err)
		require.Len(t, res.Rows, 1)
		assert.Equal(t, want.ID.UInt64(), res.Rows[0].ID.UInt64())
	})

	t.Run("filter_reference_id", func(t *testing.T) {
		want := created[7]
		res, err := provider.ListEvents(ctx, &query.ListEventsRequest{
			OrgID:       org.ID.UInt64(),
			ReferenceID: want.ReferenceID.UInt64(),
		})
		require.NoError(t, err)
		require.Len(t, res.Rows, 1)
		assert.Equal(t, want.ID.UInt64(), res.Rows[0].ID.UInt64())
	})

	t.Run("filter_time_range", func(t *testing.T) {
		after := created[5].CreatedAt.UTC()
		before := created[35].CreatedAt.UTC()
		expected := filterEvents(newestFirst, func(e *model.Event) bool {
			ts := e.CreatedAt.UTC()
			return !ts.Before(after) && ts.Before(before)
		})

		res, err := provider.ListEvents(ctx, &query.ListEventsRequest{
			OrgID:  org.ID.UInt64(),
			After:  &after,
			Before: &before,
		})
		require.NoError(t, err)
		assert.Equal(t, eventIDs(expected), eventIDs(res.Rows))
		requireNewestFirst(t, res.Rows)
		for _, event := range res.Rows {
			ts := event.CreatedAt.UTC()
			assert.False(t, ts.Before(after))
			assert.True(t, ts.Before(before))
		}
	})

	t.Run("filter_unknown_org", func(t *testing.T) {
		res, err := provider.ListEvents(ctx, &query.ListEventsRequest{
			OrgID: provider.NextID().UInt64(),
		})
		require.NoError(t, err)
		assert.Empty(t, res.Rows)
	})
}

func reverseEvents(events model.EventSlice) model.EventSlice {
	out := make(model.EventSlice, len(events))
	for i, event := range events {
		out[len(events)-1-i] = event
	}
	return out
}

func filterEvents(events model.EventSlice, match func(*model.Event) bool) model.EventSlice {
	var out model.EventSlice
	for _, event := range events {
		if match(event) {
			out = append(out, event)
		}
	}
	return out
}

func eventIDs(events model.EventSlice) []uint64 {
	ids := make([]uint64, len(events))
	for i, event := range events {
		ids[i] = event.ID.UInt64()
	}
	return ids
}

func requireNewestFirst(t *testing.T, events model.EventSlice) {
	t.Helper()
	for i := 0; i < len(events)-1; i++ {
		cur, next := events[i], events[i+1]
		curAt, nextAt := cur.CreatedAt.UTC(), next.CreatedAt.UTC()
		if curAt.Equal(nextAt) {
			require.Greater(t, cur.ID.UInt64(), next.ID.UInt64(), "id DESC at index %d", i)
			continue
		}
		require.True(t, curAt.After(nextAt), "created_at DESC at index %d: %s vs %s", i, curAt, nextAt)
	}
}
