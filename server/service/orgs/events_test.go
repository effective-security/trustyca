package orgs

import (
	"testing"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/mocks/mocktrustycadb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// wantEvent holds the fields of an expected event. Events are compared
// field by field: an xdb.ID caches its string form, so equal models are not
// always deeply equal.
type wantEvent struct {
	Type        pb.EventType_Enum
	OrgID       uint64
	ProjectID   uint64
	ReferenceID uint64
	Title       string
	Description string
}

// eventRecorder captures the events a service emits through the DB mock.
// TryCreateEvent runs on the request goroutine, so a sequential test reads
// the record without a lock.
type eventRecorder struct {
	events []*model.Event
}

// recordEvents makes db capture every emitted event
func recordEvents(db *mocktrustycadb.MockOrgsDb) *eventRecorder {
	rec := &eventRecorder{}
	db.EXPECT().TryCreateEvent(gomock.Any()).Do(func(evt *model.Event) {
		rec.events = append(rec.events, evt)
	}).AnyTimes()
	return rec
}

// requireEvent checks that want is the only event emitted since the last
// check, by the caller of testCtx, and clears the record
func (r *eventRecorder) requireEvent(t *testing.T, want wantEvent) {
	t.Helper()
	require.Len(t, r.events, 1)
	evt := r.events[0]
	r.events = nil

	require.NoError(t, evt.Validate())
	assert.Equal(t, want, wantEvent{
		Type:        evt.Type,
		OrgID:       evt.OrgID.UInt64(),
		ProjectID:   evt.ProjectID.UInt64(),
		ReferenceID: evt.ReferenceID.UInt64(),
		Title:       evt.Title,
		Description: evt.Description.String(),
	})
	assert.Equal(t, ServiceName, evt.Source.String())
	assert.Equal(t, testCallerEmail, evt.Email.String())
	assert.Nil(t, evt.Metadata)
}

// requireNone checks that no event was emitted since the last check
func (r *eventRecorder) requireNone(t *testing.T) {
	t.Helper()
	assert.Empty(t, r.events)
}
