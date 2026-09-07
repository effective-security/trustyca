package model_test

import (
	"testing"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/xdb"
	"github.com/stretchr/testify/assert"
)

const (
	testTime = "2021-01-01T00:00:00Z"
)

func TestEventResult_Pb(t *testing.T) {
	events := []*model.Event{
		{
			ID:          xdb.NewID(1),
			OrgID:       xdb.NewID(2),
			Type:        pb.EventType_OrgCreated,
			Title:       "Test Event",
			Description: xdb.NULLString("Test Description"),
			Metadata:    xdb.Metadata{"key": "value"},
			Source:      xdb.NULLString("Test Source"),
		},
	}

	result := &model.EventResult{
		Rows:        events,
		HasNextPage: true,
		NextOffset:  10,
		Cursor:      "123",
	}

	resPb := result.Pb()
	assert.Equal(t, len(events), len(resPb.Events))
	assert.Equal(t, &pb.NextPage{
		Offset: 10,
		Cursor: "123",
	}, resPb.NextPage)
}

func TestEvent_Pb(t *testing.T) {
	event := &model.Event{
		ID:          xdb.NewID(1),
		OrgID:       xdb.NewID(2),
		Type:        pb.EventType_OrgCreated,
		Title:       "Test Event",
		Description: xdb.NULLString("Test Description"),
		Metadata:    xdb.Metadata{"key": "value"},
		Source:      xdb.NULLString("Test Source"),
		CreatedAt:   xdb.ParseTime(testTime),
		ReferenceID: xdb.NewID(3),
		Email:       xdb.NULLString("test@example.com"),
	}

	assert.Equal(t, &pb.Event{
		ID:          xdb.NewID(1).String(),
		OrgID:       xdb.NewID(2).String(),
		Type:        pb.EventType_OrgCreated,
		Title:       "Test Event",
		Description: "Test Description",
		Metadata:    []*pb.KVPair{{Key: "key", Value: "value"}},
		CreatedAt:   testTime,
		ReferenceID: xdb.NewID(3).String(),
		Email:       "test@example.com",
		Source:      "Test Source",
	}, event.Pb())
}

func TestEvent_Validate(t *testing.T) {
	event := &model.Event{
		Title: "Test Event",
		Type:  pb.EventType_OrgCreated,
	}
	assert.NoError(t, event.Validate())

	event = &model.Event{
		Title: "",
		Type:  pb.EventType_Unknown,
	}
	assert.EqualError(t, event.Validate(), "invalid title")

	event = &model.Event{
		Title: "Test Event",
		Type:  pb.EventType_Unknown,
	}
	assert.EqualError(t, event.Validate(), "invalid type")
}
