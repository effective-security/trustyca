package ca

import "github.com/cockroachdb/errors"

// Errors of the issuer and profile resolution. They are returned wrapped
// with a stack, so compare them with errors.Is; the service maps them to its
// status codes.
var (
	// ErrProfileNotFound is returned when the scope has no active profile
	// with the label, in the project or in the org
	ErrProfileNotFound = errors.New("profile not found")
	// ErrIssuerNotFound is returned when the scope has no issuer with the
	// label, in the project or in the org
	ErrIssuerNotFound = errors.New("issuer not found")
	// ErrIssuerNotActive is returned when the issuer exists but does not
	// sign: it is Pending, Archived or Destroyed
	ErrIssuerNotActive = errors.New("issuer is not active")
	// ErrIssuerLabelRequired is returned when the profile binds to any
	// issuer and the request names none
	ErrIssuerLabelRequired = errors.New("issuer label is required")
	// ErrIssuerMismatch is returned when the request names an issuer other
	// than the one the profile binds to
	ErrIssuerMismatch = errors.New("issuer does not match the profile")
	// ErrProfileNotAllowed is returned when a profile bound to any issuer is
	// not listed in the AllowedProfiles of the issuer
	ErrProfileNotAllowed = errors.New("issuer does not allow the profile")
)
