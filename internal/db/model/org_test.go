package model_test

import (
	"testing"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/tests/testutils"
	"github.com/effective-security/xdb"
	"github.com/stretchr/testify/assert"
)

func TestOrgValidate(t *testing.T) {
	t.Parallel()
	tcases := []struct {
		name string
		org  model.Org
		err  string
	}{
		{
			name: "valid",
			org: model.Org{
				Alias: "cp_12345678901234567890123456789",
				Name:  "Org Name",
			},
			err: "",
		},
		{
			name: "valid alias not 32 characters",
			org: model.Org{
				Alias: "cp_12345678901234567890123456789012",
			},
			err: `invalid alias: "cp_12345678901234567890123456789012"`,
		},
		{
			name: "invalid alias not cp_ prefix",
			org: model.Org{
				Alias: "12345678901234567890123456789012",
			},
			err: `invalid alias: "12345678901234567890123456789012"`,
		},
		{
			name: "invalid name",
			org: model.Org{
				Alias: "cp_12345678901234567890123456789",
				Name:  "",
			},
			err: `invalid name: ""`,
		},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.org.Validate()
			if tc.err != "" {
				assert.EqualError(t, err, tc.err, testutils.JSON(tc.org))
			} else {
				assert.NoError(t, err, testutils.JSON(tc.org))
			}
		})
	}
}

func TestProjectPb(t *testing.T) {
	m := model.Org{
		ID:          xdb.NewID(1),
		Alias:       "cp_12345678901234567890123456789",
		Name:        "Org Name",
		Description: xdb.NULLString("a description"),
		CreatedAt:   xdb.ParseTime("2020-01-01"),
	}
	pm := m.Pb()
	assert.Equal(t, m.ID.String(), pm.ID)
	assert.Equal(t, m.Alias, pm.Alias)
	assert.Equal(t, m.Name, pm.Name)
	assert.Equal(t, string(m.Description), pm.Description)
	assert.Equal(t, m.CreatedAt.String(), pm.CreatedAt)
}

func TestProjectResult_Pb(t *testing.T) {
	orgs := []*model.Org{
		{ID: xdb.NewID(1), Name: "Org 1"},
		{ID: xdb.NewID(2), Name: "Org 2"},
	}

	result := &model.OrgResult{
		Rows:        orgs,
		HasNextPage: true,
		NextOffset:  10,
		Cursor:      "123",
	}

	resPb := result.Pb()
	assert.Equal(t, len(orgs), len(resPb.Orgs))
	assert.Equal(t, &pb.NextPage{
		Offset: 10,
		Cursor: "123",
	}, resPb.NextPage)
}
