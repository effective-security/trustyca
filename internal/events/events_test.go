package events_test

import (
	"context"
	"testing"
	"time"

	"github.com/effective-security/porto/xhttp/identity"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/authctx"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/events"
	"github.com/effective-security/xdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type recorder struct {
	events []*model.Event
}

func (r *recorder) TryCreateEvent(evt *model.Event) {
	r.events = append(r.events, evt)
}

func TestEvent_Emit(t *testing.T) {
	rec := &recorder{}

	// no caller identity: email comes only from an explicit override
	ctx := context.Background()
	events.New(ctx, "test", pb.EventType_ProjectCreated, "Project created").
		Project(xdb.NewID(1)).
		Reference(xdb.NewID(2)).
		Description("project %q created", "p1").
		Meta("name", "p1").
		Meta("empty", "").
		Emit(rec)

	require.Len(t, rec.events, 1)
	evt := rec.events[0]
	assert.NoError(t, evt.Validate())
	assert.Equal(t, pb.EventType_ProjectCreated, evt.Type)
	assert.Equal(t, "Project created", evt.Title)
	assert.EqualValues(t, 1, evt.ProjectID.UInt64())
	assert.EqualValues(t, 0, evt.OrgID.UInt64())
	assert.EqualValues(t, 2, evt.ReferenceID.UInt64())
	assert.Equal(t, `project "p1" created`, evt.Description.String())
	assert.Equal(t, "test", evt.Source.String())
	assert.Equal(t, "", evt.Email.String())
	assert.Equal(t, xdb.Metadata{"name": "p1"}, evt.Metadata)
	_, hasEmpty := evt.Metadata["empty"]
	assert.False(t, hasEmpty)

	// caller identity supplies the email
	idn := identity.NewIdentity("user", "1", "", map[string]any{"email": "denis@example.com"}, "tok", "Bearer", identity.MethodJWT)
	ctx = authctx.NewTrustyCtx(ctx, identity.NewRequestContext(idn, ""))
	e := events.New(ctx, "test", pb.EventType_OrgUpdated, "Billing account updated").
		Org(xdb.NewID(5))
	assert.Equal(t, "denis@example.com", e.Model().Email.String())
	assert.Nil(t, e.Model().Metadata)
	assert.NoError(t, e.Model().Validate())

	// an explicit email wins; an empty one changes nothing
	e.Email("")
	assert.Equal(t, "denis@example.com", e.Model().Email.String())
	e.Email("other@example.com")
	assert.Equal(t, "other@example.com", e.Model().Email.String())
	e.Emit(rec)
	require.Len(t, rec.events, 2)
	assert.Same(t, e.Model(), rec.events[1])
}

func TestParseTimeRange(t *testing.T) {
	from, to, err := events.ParseTimeRange("", "")
	require.NoError(t, err)
	assert.Nil(t, from)
	assert.Nil(t, to)

	from, to, err = events.ParseTimeRange("2026-01-02T03:04:05Z", "")
	require.NoError(t, err)
	require.NotNil(t, from)
	assert.Equal(t, time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), from.UTC())
	assert.Nil(t, to)

	from, to, err = events.ParseTimeRange("", "2026-01-02T03:04:05Z")
	require.NoError(t, err)
	assert.Nil(t, from)
	require.NotNil(t, to)
	assert.Equal(t, time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), to.UTC())

	from, to, err = events.ParseTimeRange("2026-01-01T00:00:00Z", "2026-01-02T00:00:00+02:00")
	require.NoError(t, err)
	require.NotNil(t, from)
	require.NotNil(t, to)
	assert.True(t, to.After(*from))

	_, _, err = events.ParseTimeRange("yesterday", "")
	assert.EqualError(t, err, `invalid After: "yesterday" is not RFC3339`)
	_, _, err = events.ParseTimeRange("", "2026-01-02")
	assert.EqualError(t, err, `invalid Before: "2026-01-02" is not RFC3339`)
	_, _, err = events.ParseTimeRange("2026-01-02T00:00:00Z", "2026-01-02T00:00:00Z")
	assert.EqualError(t, err, "invalid time range: Before must be later than After")
	_, _, err = events.ParseTimeRange("2026-01-03T00:00:00Z", "2026-01-02T00:00:00Z")
	assert.EqualError(t, err, "invalid time range: Before must be later than After")
}
