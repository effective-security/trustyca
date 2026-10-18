package model

import (
	"github.com/cockroachdb/errors"
	"github.com/effective-security/xdb"
)

// Column length limits of the CA tables
const (
	// MaxLenForLabel is the length of issuer and profile labels, and of the
	// key identifiers and serial numbers
	MaxLenForLabel = 64
	// MaxLenForName is the length of subject and issuer names, and of the
	// certificate label, locations and revocation text
	MaxLenForName = 260
	// MaxLenForSha256 is the length of a hex encoded SHA-256 thumbprint
	MaxLenForSha256 = 64
)

// validateTenancy checks the tenancy of a CA row: a platform row has neither
// org nor project, an org row has an org only, and a project row has both.
func validateTenancy(orgID, projectID xdb.ID) error {
	if !projectID.IsZero() && orgID.IsZero() {
		return errors.New("invalid org ID: a project scope requires an org")
	}
	return nil
}

// validateLength checks that a required column value fits its length limit
func validateLength(name, val string, maxLen int, required bool) error {
	if required && val == "" {
		return errors.Errorf("invalid %s: required", name)
	}
	if len(val) > maxLen {
		return errors.Errorf("invalid %s length: %d", name, len(val))
	}
	return nil
}
