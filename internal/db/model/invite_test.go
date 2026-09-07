package model

import (
	"testing"

	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/xdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInviteValidate(t *testing.T) {
	t.Parallel()
	tcases := []struct {
		name   string
		invite Invite
		err    string
	}{
		{
			name: "valid",
			invite: Invite{
				OrgID:     xdb.NewID(1),
				InviterID: xdb.NewID(2),
				Email:     "invitee@example.com",
				Role:      pb.Role_User,
			},
			err: "",
		},
		{
			name:   "invalid org_id",
			invite: Invite{InviterID: xdb.NewID(2), Email: "invitee@example.com", Role: pb.Role_User},
			err:    "invalid org_id",
		},
		{
			name:   "invalid inviter_id",
			invite: Invite{OrgID: xdb.NewID(1), Email: "invitee@example.com", Role: pb.Role_User},
			err:    "invalid inviter_id",
		},
		{
			name:   "invalid email",
			invite: Invite{OrgID: xdb.NewID(1), InviterID: xdb.NewID(2), Role: pb.Role_User},
			err:    `invalid email: ""`,
		},
		{
			name:   "invalid role",
			invite: Invite{OrgID: xdb.NewID(1), InviterID: xdb.NewID(2), Email: "invitee@example.com"},
			err:    "invalid role",
		},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.invite.Validate()
			if tc.err != "" {
				require.Error(t, err)
				assert.Equal(t, tc.err, err.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
