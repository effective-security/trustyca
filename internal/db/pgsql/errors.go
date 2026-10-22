package pgsql

import (
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/lib/pq"
)

// The unique constraints of the CA tables, as PostgreSQL names them in a
// violation (SQLSTATE 23505)
const (
	// UniqueIssuerLabel is the label of an issuer in its org and project
	UniqueIssuerLabel = "unique_issuer_org_project_label"
	// UniqueIssuerSkid is the key identifier of an issuer, across the table
	UniqueIssuerSkid = "unique_issuer_skid"
	// UniqueCertificatePrefix is the prefix of the unique constraints of the
	// certificate table: the thumbprint, and the issuer and serial pair
	UniqueCertificatePrefix = "unique_certificate"
)

// uniqueViolationCode is the SQLSTATE of a unique constraint violation
const uniqueViolationCode = "23505"

// uniqueViolationMessage is how the driver words a unique violation; the
// fakes of the tests fail with the same message
const uniqueViolationMessage = "violates unique constraint"

// IsUniqueViolation reports whether the error is a unique constraint
// violation of a constraint whose name starts with the prefix; an empty
// prefix matches every unique constraint. The driver's error is matched by
// its SQLSTATE and constraint name; an error that only carries the
// driver's message, as the fakes of the tests return, by the message.
func IsUniqueViolation(err error, prefix string) bool {
	if err == nil {
		return false
	}
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		return pqErr.Code == uniqueViolationCode && strings.HasPrefix(pqErr.Constraint, prefix)
	}
	msg := err.Error()
	return strings.Contains(msg, uniqueViolationMessage) && strings.Contains(msg, prefix)
}
