package model

import (
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
)

// ProjectAliasPrefix is used for generated project aliases
const ProjectAliasPrefix = "prj_"

// Validate returns error if the model is not valid
func (m *Project) Validate() error {
	if m.OrgID.UInt64() == 0 {
		return errors.Errorf("invalid org_id")
	}
	alias := strings.TrimSpace(m.Alias)
	if alias == "" || len(alias) > 64 || alias != m.Alias {
		return errors.Errorf("invalid alias: %q", m.Alias)
	}
	if m.Name == "" || len(m.Name) > 64 {
		return errors.Errorf("invalid name: %q", m.Name)
	}
	return nil
}

// Pb converts model to proto
func (m *Project) Pb() *pb.Project {
	return &pb.Project{
		ID:          m.ID.String(),
		OrgID:       m.OrgID.String(),
		Alias:       m.Alias,
		Name:        m.Name,
		Description: string(m.Description),
		Status:      m.Status,
		CreatedAt:   m.CreatedAt.String(),
		UpdatedAt:   m.UpdatedAt.String(),
	}
}

// Pb converts slice of model to proto
func (m ProjectSlice) Pb() []*pb.Project {
	res := make([]*pb.Project, 0, len(m))
	for _, v := range m {
		res = append(res, v.Pb())
	}
	return res
}

// NextPage returns the next page of the result
func (v *ProjectResult) NextPage() *pb.NextPage {
	if v.HasNextPage {
		return &pb.NextPage{
			Offset: v.NextOffset,
			Cursor: v.Cursor,
		}
	}
	return nil
}

// Pb converts model to proto
func (v *ProjectResult) Pb() *pb.ProjectsResponse {
	return &pb.ProjectsResponse{
		Projects: ProjectSlice(v.Rows).Pb(),
		NextPage: v.NextPage(),
	}
}
