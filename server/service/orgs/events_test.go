package orgs

import (
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/authctx"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/mocks/mocktrustycadb"
	"github.com/effective-security/xdb"
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

func TestService_ListEvents(t *testing.T) {
	ctrl := gomock.NewController(t)
	db := mocktrustycadb.NewMockOrgsDb(ctrl)
	svc := Service{db: db, authorizer: newFakeAuthorizer(
		orgGrant(42, pb.Role_Admin),
		projectGrant(7, 201, pb.Role_Viewer),
	)}
	admin := testCtx("42", "1")
	member := testCtx("7", "1")
	stranger := testCtx("8", "1")

	_, err := svc.ListEvents(testCtx("42", ""), &pb.ListEventsRequest{})
	assert.EqualError(t, err, "forbidden: org not selected")

	at := xdb.Time(time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC))
	row := &model.Event{
		ID:        xdb.NewID(5),
		OrgID:     xdb.NewID(1),
		Type:      pb.EventType_OrgUpdated,
		Title:     "Org updated",
		Email:     xdb.NULLString(testCallerEmail),
		Source:    xdb.NULLString(ServiceName),
		CreatedAt: at,
	}
	next := query.EncodeTimeCursor(at, row.ID)
	first := query.NewCursor(0)

	// an org Admin lists every event of the org; an empty cursor is the
	// first page of cursor pagination
	db.EXPECT().ListEvents(gomock.Any(), &query.ListEventsRequest{OrgID: 1, Limit: xdb.DefaultPageSize, Cursor: first}).Return(&model.EventResult{
		Rows:        model.EventSlice{row},
		HasNextPage: true,
		Cursor:      next,
	}, nil)
	list, err := svc.ListEvents(admin, &pb.ListEventsRequest{})
	require.NoError(t, err)
	require.Len(t, list.Events, 1)
	assert.Equal(t, "5", list.Events[0].ID)
	assert.Equal(t, pb.EventType_OrgUpdated, list.Events[0].Type)
	assert.Equal(t, testCallerEmail, list.Events[0].Email)
	require.NotNil(t, list.NextPage)
	assert.Equal(t, next, list.NextPage.Cursor)
	assert.Zero(t, list.NextPage.Offset)

	// the cursor of the previous page continues the listing, with the filters
	cursor, err := query.ParseTimeCursor(next)
	require.NoError(t, err)
	after := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	before := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	db.EXPECT().ListEvents(gomock.Any(), &query.ListEventsRequest{
		OrgID:  1,
		Type:   pb.EventType_OrgUpdated,
		After:  &after,
		Before: &before,
		Limit:  5,
		Cursor: cursor,
	}).Return(&model.EventResult{}, nil)
	list, err = svc.ListEvents(admin, &pb.ListEventsRequest{
		Type:   pb.EventType_OrgUpdated,
		After:  "2026-10-01T00:00:00Z",
		Before: "2026-11-01T00:00:00Z",
		Limit:  5,
		Cursor: next,
	})
	require.NoError(t, err)
	assert.Empty(t, list.Events)
	assert.Nil(t, list.NextPage)

	// a member with project grants only sees the org-wide events and those
	// of its projects
	db.EXPECT().ListEvents(gomock.Any(), &query.ListEventsRequest{OrgID: 1, ProjectIDs: []uint64{201}, Limit: xdb.DefaultPageSize, Cursor: first}).Return(&model.EventResult{
		Rows: model.EventSlice{row},
	}, nil)
	list, err = svc.ListEvents(member, &pb.ListEventsRequest{Cursor: query.InitialCursor})
	require.NoError(t, err)
	require.Len(t, list.Events, 1)

	// the events of one project when the request names it
	db.EXPECT().ListEvents(gomock.Any(), &query.ListEventsRequest{OrgID: 1, ProjectID: 201, Limit: xdb.DefaultPageSize, Cursor: first}).Return(&model.EventResult{}, nil)
	_, err = svc.ListEvents(member, &pb.ListEventsRequest{ProjectID: "201"})
	require.NoError(t, err)

	// a user without a grant in the org sees nothing, without a DB call
	list, err = svc.ListEvents(stranger, &pb.ListEventsRequest{})
	require.NoError(t, err)
	assert.Empty(t, list.Events)

	// a project of another org or an inactive project is not found
	_, err = svc.ListEvents(admin, &pb.ListEventsRequest{ProjectID: "301"})
	assert.EqualError(t, err, "not_found: project not found")
	_, err = svc.ListEvents(admin, &pb.ListEventsRequest{ProjectID: "203"})
	assert.EqualError(t, err, "not_found: project not found")
	_, err = svc.ListEvents(admin, &pb.ListEventsRequest{ProjectID: "abc"})
	assert.EqualError(t, err, "bad_request: invalid project ID")

	// the time range and the cursor are validated before the query
	_, err = svc.ListEvents(admin, &pb.ListEventsRequest{After: "yesterday"})
	assert.EqualError(t, err, `bad_request: invalid After: "yesterday" is not RFC3339`)
	_, err = svc.ListEvents(admin, &pb.ListEventsRequest{After: "2026-10-02T00:00:00Z", Before: "2026-10-01T00:00:00Z"})
	assert.EqualError(t, err, "bad_request: invalid time range: Before must be later than After")
	_, err = svc.ListEvents(admin, &pb.ListEventsRequest{Cursor: "not a cursor"})
	assert.EqualError(t, err, "bad_request: invalid cursor")
	// the cursor of a list by name is not a cursor of the events
	_, err = svc.ListEvents(admin, &pb.ListEventsRequest{Cursor: query.EncodeNameCursor("Test", xdb.NewID(201))})
	assert.EqualError(t, err, "bad_request: invalid cursor")

	db.EXPECT().ListEvents(gomock.Any(), gomock.Any()).Return(nil, errors.New("db failed"))
	_, err = svc.ListEvents(admin, &pb.ListEventsRequest{})
	assert.EqualError(t, err, "unexpected: failed to list events")

	// an org-wide API key lists every event of the org, a restricted key
	// the events of its project only
	db.EXPECT().ListEvents(gomock.Any(), &query.ListEventsRequest{OrgID: 1, Limit: xdb.DefaultPageSize, Cursor: first}).Return(&model.EventResult{}, nil)
	_, err = svc.ListEvents(apiKeyCtx("1", "", "org:read"), &pb.ListEventsRequest{})
	require.NoError(t, err)
	db.EXPECT().ListEvents(gomock.Any(), &query.ListEventsRequest{OrgID: 1, ProjectID: 201, Limit: xdb.DefaultPageSize, Cursor: first}).Return(&model.EventResult{}, nil)
	_, err = svc.ListEvents(apiKeyCtx("1", "201", "org:read"), &pb.ListEventsRequest{})
	require.NoError(t, err)
	_, err = svc.ListEvents(apiKeyCtx("1", "201", "org:read"), &pb.ListEventsRequest{ProjectID: "203"})
	assert.EqualError(t, err, "not_found: project not found")
}

// TestService_ListEvents_CheckAccess checks the authorization of the method
// at the interceptor: Viewer at the org, or at the project of the request,
// and an API key with org:read
func TestService_ListEvents_CheckAccess(t *testing.T) {
	auth := newFakeAuthorizer(
		orgGrant(42, pb.Role_Viewer),
		projectGrant(7, 201, pb.Role_Viewer),
	)
	method := pb.Orgs_ListEvents_FullMethodName
	var _ authctx.ProjectRequester = (*pb.ListEventsRequest)(nil)

	require.NoError(t, authctx.CheckAccess(testCtx("42", "1"), auth, &pb.ListEventsRequest{}, method))
	require.NoError(t, authctx.CheckAccess(testCtx("42", "1"), auth, &pb.ListEventsRequest{ProjectID: "201"}, method))
	// a member with project grants only is the derived org Viewer
	require.NoError(t, authctx.CheckAccess(testCtx("7", "1"), auth, &pb.ListEventsRequest{}, method))
	require.NoError(t, authctx.CheckAccess(testCtx("7", "1"), auth, &pb.ListEventsRequest{ProjectID: "201"}, method))
	err := authctx.CheckAccess(testCtx("7", "1"), auth, &pb.ListEventsRequest{ProjectID: "203"}, method)
	assert.EqualError(t, err, "forbidden: access denied, action: /pb.Orgs/ListEvents")
	err = authctx.CheckAccess(testCtx("8", "1"), auth, &pb.ListEventsRequest{}, method)
	assert.EqualError(t, err, "forbidden: insufficient role, action: /pb.Orgs/ListEvents")

	require.NoError(t, authctx.CheckAccess(apiKeyCtx("1", "", "org:read"), auth, &pb.ListEventsRequest{}, method))
	require.NoError(t, authctx.CheckAccess(apiKeyCtx("1", "201", "org:read"), auth, &pb.ListEventsRequest{}, method))
	err = authctx.CheckAccess(apiKeyCtx("1", "", "ca:read"), auth, &pb.ListEventsRequest{}, method)
	assert.EqualError(t, err, "forbidden: insufficient scope, action: /pb.Orgs/ListEvents")
	err = authctx.CheckAccess(apiKeyCtx("1", "201", "org:read"), auth, &pb.ListEventsRequest{ProjectID: "203"}, method)
	assert.EqualError(t, err, "forbidden: project mismatch, action: /pb.Orgs/ListEvents")
}
