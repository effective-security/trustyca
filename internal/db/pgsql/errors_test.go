package pgsql_test

import (
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/internal/db/pgsql"
	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
)

func TestIsUniqueViolation(t *testing.T) {
	t.Parallel()
	driverErr := &pq.Error{Code: "23505", Constraint: pgsql.UniqueIssuerLabel, Message: "duplicate key value violates unique constraint"}
	wrapped := errors.WithMessage(errors.WithStack(driverErr), "unable to register issuer")
	fake := errors.New(`pq: duplicate key value violates unique constraint "unique_certificate_sha256"`)

	for _, tc := range []struct {
		name   string
		err    error
		prefix string
		want   bool
	}{
		{"nil", nil, "", false},
		{"driver any", driverErr, "", true},
		{"driver exact", driverErr, pgsql.UniqueIssuerLabel, true},
		{"driver other", driverErr, pgsql.UniqueIssuerSkid, false},
		{"driver wrapped", wrapped, pgsql.UniqueIssuerLabel, true},
		{"driver other code", &pq.Error{Code: "23503", Constraint: pgsql.UniqueIssuerLabel}, "", false},
		{"message prefix", fake, pgsql.UniqueCertificatePrefix, true},
		{"message other", fake, pgsql.UniqueIssuerLabel, false},
		{"message any", fake, "", true},
		{"other error", errors.New("connection reset"), "", false},
	} {
		assert.Equal(t, tc.want, pgsql.IsUniqueViolation(tc.err, tc.prefix), tc.name)
	}
}
