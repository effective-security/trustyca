package model

import (
	"github.com/cockroachdb/errors"
	"github.com/effective-security/xdb"
)

// Validate returns error if the model is not valid
func (m *Invite) Validate() error {
	if m.OrgID.UInt64() == 0 {
		return errors.Errorf("invalid org_id")
	}
	if m.InviterID.UInt64() == 0 {
		return errors.Errorf("invalid inviter_id")
	}
	if m.Email == "" || len(m.Email) > xdb.MaxLenForEmail {
		return errors.Errorf("invalid email: %q", m.Email)
	}
	if m.Role == 0 {
		return errors.Errorf("invalid role")
	}
	return nil
}
