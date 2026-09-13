package model

import (
	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
)

// NextPage returns the next page of the result
func (v *EventResult) NextPage() *pb.NextPage {
	if v.HasNextPage {
		return &pb.NextPage{
			Offset: v.NextOffset,
			Cursor: v.Cursor,
		}
	}
	return nil
}

// Pb returns pb.Events
func (v *EventResult) Pb() *pb.EventsResponse {
	res := &pb.EventsResponse{
		Events:   make([]*pb.Event, len(v.Rows)),
		NextPage: v.NextPage(),
	}
	for i, e := range v.Rows {
		res.Events[i] = e.Pb()
	}
	return res
}

// Pb returns pb.Event
func (v *Event) Pb() *pb.Event {
	evt := &pb.Event{
		ID:          v.ID.String(),
		OrgID:       v.OrgID.String(),
		ProjectID:   v.ProjectID.String(),
		Type:        v.Type,
		Title:       v.Title,
		Description: string(v.Description),
		Metadata:    pb.FlatMap(v.Metadata),
		CreatedAt:   v.CreatedAt.String(),
		ReferenceID: v.ReferenceID.String(),
		Email:       v.Email.String(),
		Source:      v.Source.String(),
	}
	return evt
}

// Validate the model
func (m *Event) Validate() error {
	if m.Title == "" {
		return errors.New("invalid title")
	}
	if m.Type == pb.EventType_Unknown {
		return errors.New("invalid type")
	}
	return nil
}
