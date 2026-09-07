package model

import (
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
)

// Validate returns error if the model is not valid
func (m *Org) Validate() error {
	if len(m.Alias) != 32 || !strings.HasPrefix(m.Alias, "cp_") {
		return errors.Errorf("invalid alias: %q", m.Alias)
	}
	if m.Name == "" || len(m.Name) > 64 {
		return errors.Errorf("invalid name: %q", m.Name)
	}
	return nil
}

// Pb converts model to proto
func (m *Org) Pb() *pb.Org {
	return &pb.Org{
		ID:          m.ID.String(),
		Alias:       m.Alias,
		Name:        m.Name,
		Description: string(m.Description),
		Status:      m.Status,
		CreatedAt:   m.CreatedAt.String(),
	}
}

// NextPage returns the next page of the result
func (v *OrgResult) NextPage() *pb.NextPage {
	if v.HasNextPage {
		return &pb.NextPage{
			Offset: v.NextOffset,
			Cursor: v.Cursor,
		}
	}
	return nil
}

// Pb converts model to proto
func (v *OrgResult) Pb() *pb.OrgsResponse {
	res := &pb.OrgsResponse{
		Orgs:     make([]*pb.Org, len(v.Rows)),
		NextPage: v.NextPage(),
	}
	for i, p := range v.Rows {
		res.Orgs[i] = p.Pb()
	}
	return res
}
