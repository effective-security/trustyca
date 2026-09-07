package model_test

import (
	"fmt"
	"testing"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/tests/testutils"
	"github.com/effective-security/xdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	longVal = "hlvksjdhfvlkjsdfhlbkshjdflkjvhsldfkjvhlskdfjvhlakjfvhlakjfvhlakjhvlkajshvlkajshvlkjahsdlvkjahslkvjhalskdjvhaklsdvjhaklsjdvhalksjvhalkjsvhlakshvakljshvlkasjhvkajshvkajhvkajhlvkahlfkvj"
	longURL = "http://jfhsdjfghsjdfghsdfg.sdfhgslkfdhgslkjdfhglskjdfhgslkjdfhglskdjfhglskjdfhgslkdjfhglksjdfhgskjdfhglksjdfhglksjdfhg.com?hlvksjdhfvlkjsdfhlbkshjdflkjvhsldfkjvhlskdfjvhlakjfvhlakjfvhlakjhvlkajshvlkajshvlkjahsdlvkjahslkvjhalskdjvhaklsdvjhaklsjdvhalksjvhalkjsvhlakshvakljshvlkasjhvkajshvkajhvkajhlvkahlfkvj"
)

func TestLogin(t *testing.T) {
	tcases := []struct {
		u   *model.Login
		err string
	}{
		{&model.Login{}, "invalid external_id: \"\""},
		{&model.Login{ExternalID: "123"}, "invalid name: \"\""},
		{&model.Login{ExternalID: "123", Name: longVal}, fmt.Sprintf("invalid name: %q", longVal)},
		{&model.Login{ExternalID: "123", Name: "n1", Email: longVal}, fmt.Sprintf("invalid email: %q", longVal)},
		{&model.Login{ExternalID: "123", Name: "n1", Email: "email", Provider: pb.IDP_Undefined}, "invalid provider"},
	}
	for _, tc := range tcases {
		err := tc.u.Validate()
		if tc.err != "" {
			require.Error(t, err)
			assert.Equal(t, tc.err, err.Error())
		} else {
			assert.NoError(t, err)
		}
	}
}

func TestLoginModel(t *testing.T) {
	m := model.Login{
		ID:         xdb.MustID("1"),
		ExternalID: "123",
		Name:       "n1",
		Email:      "email",
		Provider:   pb.IDP_Github,
		Count:      1,
		LastAt:     xdb.ParseTime("2020-01-01"),
	}
	err := m.Validate()
	require.NoError(t, err)

	pm := m.Pb()
	assert.Equal(t, m.ID.String(), pm.ID)
	assert.Equal(t, m.ExternalID, pm.ExternalID)
	assert.Equal(t, uint32(m.Count), pm.LoginCount)
}

func TestUser(t *testing.T) {
	tcases := []struct {
		u   *model.User
		err string
	}{
		{&model.User{}, "invalid name: \"\""},
		{&model.User{Name: longVal}, fmt.Sprintf("invalid name: %q", longVal)},
		{&model.User{Name: "n1", Email: longVal}, fmt.Sprintf("invalid email: %q", longVal)},
	}
	for _, tc := range tcases {
		err := tc.u.Validate()
		if tc.err != "" {
			require.Error(t, err)
			assert.Equal(t, tc.err, err.Error())
		} else {
			assert.NoError(t, err)
		}
	}

	var u model.User
	testutils.PopulateObject(&u, "db")

	dto := u.Pb()
	u2, err := model.NewUser(dto)
	require.NoError(t, err)
	assert.Equal(t, u.ID.String(), u2.ID.String())

	dto.ID = "----"
	_, err = model.NewUser(dto)
	assert.EqualError(t, err, "invalid ID: '----'")

	dto.ID = "1O0"
	_, err = model.NewUser(dto)
	assert.EqualError(t, err, "invalid ID: '1O0'")

	m := model.User{ID: xdb.NewID(123), Name: "n1", Email: "e1", EmailVerified: true}
	err = m.Validate()
	require.NoError(t, err)
}

func TestInvitePb(t *testing.T) {
	m := model.Invite{
		ID:        xdb.NewID(1),
		OrgID:     xdb.NewID(2),
		InviterID: xdb.NewID(3),
		Email:     "invitee@example.com",
		Role:      pb.Role_User,
		CreatedAt: xdb.ParseTime("2020-01-01"),
	}
	pm := m.Pb()
	assert.Equal(t, m.ID.String(), pm.ID)
	assert.Equal(t, m.OrgID.String(), pm.OrgID)
	assert.Equal(t, m.InviterID.String(), pm.InviterID)
	assert.Equal(t, m.Email, pm.Email)
	assert.Equal(t, m.Role, pm.Role)
	assert.Equal(t, m.CreatedAt.String(), pm.CreatedAt)
}

func TestFindLoginByID(t *testing.T) {
	list := model.LoginSlice{
		{ID: xdb.NewID(1)},
		{ID: xdb.NewID(2)},
	}
	found := model.FindLoginByID(list, xdb.NewID(2).String())
	require.NotNil(t, found)
	assert.Equal(t, xdb.NewID(2).String(), found.ID.String())

	assert.Nil(t, model.FindLoginByID(list, xdb.NewID(3).String()))
}
