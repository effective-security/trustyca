package model

import (
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
)

// Validate returns error if the model is not valid
func (m *APIKey) Validate() error {
	if m.OrgID.IsZero() {
		return errors.New("invalid org ID")
	}
	if m.Label == "" || len(m.Label) > 255 {
		return errors.New("invalid label length")
	}
	if m.Status == pb.ItemStatus_Unknown {
		return errors.New("invalid key status")
	}
	if m.Key == "" || len(m.Key) > 128 {
		return errors.New("invalid key length")
	}
	if len(m.Secret) > 128 {
		return errors.New("invalid secret length")
	}
	if len(m.Scopes) == 0 {
		return errors.New("invalid scopes")
	}
	for _, scope := range m.Scopes {
		if scope == "" || len(scope) > 128 {
			return errors.Errorf("invalid scope length: %s", scope)
		}
	}
	return nil
}

// IsExpired returns true if the key has an expiry in the past
func (m *APIKey) IsExpired(now time.Time) bool {
	t := m.ExpiresAt.UTC()
	return !t.IsZero() && t.Before(now)
}

// Pb converts model to proto; the secret is never returned
func (m *APIKey) Pb() *pb.APIKey {
	return &pb.APIKey{
		ID:        m.ID.String(),
		OrgID:     m.OrgID.String(),
		ProjectID: m.ProjectID.String(),
		Label:     m.Label,
		Scopes:    m.Scopes,
		Key:       m.Key,
		Status:    m.Status,
		CreatedAt: m.CreatedAt.String(),
		UsedAt:    m.UsedAt.String(),
		UsedCount: m.UsedCount,
		ExpiresAt: m.ExpiresAt.String(),
		Metadata:  pb.FlatMap(m.Metadata),
		// The secret is not returned in the API
		// Call GetAPIKeySecret to get the secret
		//Secret: m.Secret,
	}
}

// NextPage returns the next page of the result
func (m *APIKeyResult) NextPage() *pb.NextPage {
	if m.HasNextPage {
		return &pb.NextPage{
			Offset: m.NextOffset,
			Cursor: m.Cursor,
		}
	}
	return nil
}

// Pb converts model to proto
func (m *APIKeyResult) Pb() *pb.APIKeysResponse {
	res := &pb.APIKeysResponse{
		APIKeys:  make([]*pb.APIKey, len(m.Rows)),
		NextPage: m.NextPage(),
	}
	for i, r := range m.Rows {
		res.APIKeys[i] = r.Pb()
	}
	return res
}
