package model

import (
	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/xdb"
)

// Pb converts model to proto
func (u *User) Pb() *pb.UserInfo {
	user := &pb.UserInfo{
		ID:            u.ID.String(),
		Name:          u.Name,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
	}

	return user
}

// Pb converts model to proto
func (u *Login) Pb() *pb.LoginInfo {
	login := &pb.LoginInfo{
		ID:            u.ID.String(),
		ExternalID:    u.ExternalID,
		Provider:      u.Provider,
		Name:          u.Name,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		LoginCount:    uint32(u.Count),
		LastLoginAt:   u.LastAt.String(),
	}

	return login
}

// Validate returns error if the model is not valid
func (u *User) Validate() error {
	if u.Name == "" || len(u.Name) > xdb.MaxLenForName {
		return errors.Errorf("invalid name: %q", u.Name)
	}
	if u.Email == "" || len(u.Email) > xdb.MaxLenForEmail {
		return errors.Errorf("invalid email: %q", u.Email)
	}
	return nil
}

// Validate returns error if the model is not valid
func (u *Login) Validate() error {
	if u.ExternalID == "" || len(u.ExternalID) > xdb.MaxLenForName {
		return errors.Errorf("invalid external_id: %q", u.ExternalID)
	}
	if u.Name == "" || len(u.Name) > xdb.MaxLenForName {
		return errors.Errorf("invalid name: %q", u.Name)
	}
	if u.Email == "" || len(u.Email) > xdb.MaxLenForEmail {
		return errors.Errorf("invalid email: %q", u.Email)
	}
	if u.Provider == pb.IDP_Undefined {
		return errors.Errorf("invalid provider")
	}
	return nil
}

// NewUser returns User from Dto
func NewUser(u *pb.UserInfo) (*User, error) {
	id, err := xdb.ParseID(u.ID)
	if err != nil {
		return nil, err
	}

	user := &User{
		ID:            id,
		Name:          u.Name,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
	}

	return user, nil
}

// FindLoginByID returns Login if found
func FindLoginByID(list []*Login, uid string) *Login {
	for _, l := range list {
		if l.ID.String() == uid {
			return l
		}
	}
	return nil
}
