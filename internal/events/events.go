package events

import (
	"context"
	"fmt"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/authctx"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/xdb"
)

// Recorder records events without blocking the caller
type Recorder interface {
	// TryCreateEvent records an event in the background, logging a failure
	// instead of returning it
	TryCreateEvent(evt *model.Event)
}

// Event builds a model.Event for one action
type Event struct {
	evt *model.Event
}

// New starts an event of the given type. The actor's email is taken from
// the caller identity in ctx, when there is one; source names the component
// that emits the event, such as a service name.
func New(ctx context.Context, source string, typ pb.EventType_Enum, title string) *Event {
	evt := &model.Event{
		Type:   typ,
		Title:  title,
		Source: xdb.NULLString(source),
	}
	if email := authctx.FromContext(ctx).Email(); email != "" {
		evt.Email = xdb.NULLString(email)
	}
	return &Event{evt: evt}
}

// Project scopes the event to a project
func (e *Event) Project(id xdb.ID) *Event {
	e.evt.ProjectID = id
	return e
}

// Org scopes the event to an organization
func (e *Event) Org(id xdb.ID) *Event {
	e.evt.OrgID = id
	return e
}

// Reference sets the ID of the entity the event is about, such as the org,
// project, user, invite or API key
func (e *Event) Reference(id xdb.ID) *Event {
	e.evt.ReferenceID = id
	return e
}

// Email overrides the actor's email, for flows where the caller identity
// does not carry it
func (e *Event) Email(email string) *Event {
	if email != "" {
		e.evt.Email = xdb.NULLString(email)
	}
	return e
}

// Description sets the human readable details of the event
func (e *Event) Description(format string, args ...any) *Event {
	e.evt.Description = xdb.NULLString(fmt.Sprintf(format, args...))
	return e
}

// Meta adds a metadata entry; an empty value is skipped
func (e *Event) Meta(key, value string) *Event {
	if value == "" {
		return e
	}
	if e.evt.Metadata == nil {
		e.evt.Metadata = xdb.Metadata{}
	}
	e.evt.Metadata[key] = value
	return e
}

// Model returns the built event
func (e *Event) Model() *model.Event {
	return e.evt
}

// Emit records the event through r, in the background
func (e *Event) Emit(r Recorder) {
	r.TryCreateEvent(e.evt)
}

// ParseTimeRange parses the RFC3339 bounds of a list request. An empty
// bound is unbounded and returns nil.
func ParseTimeRange(after, before string) (*time.Time, *time.Time, error) {
	var from, to *time.Time
	if after != "" {
		t, err := time.Parse(time.RFC3339, after)
		if err != nil {
			return nil, nil, errors.Errorf("invalid After: %q is not RFC3339", after)
		}
		from = &t
	}
	if before != "" {
		t, err := time.Parse(time.RFC3339, before)
		if err != nil {
			return nil, nil, errors.Errorf("invalid Before: %q is not RFC3339", before)
		}
		to = &t
	}
	if from != nil && to != nil && !to.After(*from) {
		return nil, nil, errors.New("invalid time range: Before must be later than After")
	}
	return from, to, nil
}
