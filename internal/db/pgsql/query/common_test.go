package query_test

import (
	"testing"

	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/internal/db/schema"
	"github.com/effective-security/trustyca/tests/testutils"
	"github.com/stretchr/testify/assert"
)

type tcase struct {
	f    query.BuildQueryFunc
	args []any
	exp  string
}

func check(t *testing.T, tcases []tcase) {
	firstFail := true
	for _, tc := range tcases {
		qstr, name := tc.f(tc.args...)
		if !assert.Equal(t, tc.exp, qstr, "Failed: %s, params: %s", name, testutils.JSON(tc.args)) {
			firstFail = true
		}
	}
	// second run should get from cache
	if !firstFail {
		for _, tc := range tcases {
			qstr, name := tc.f(tc.args...)
			assert.Equal(t, tc.exp, qstr, "Failed: %s, params: %s", name, testutils.JSON(tc.args))
		}
	}
}

func Test_CommonQueries(t *testing.T) {
	t.Parallel()

	check(t, []tcase{
		{
			query.GetRowByID, []any{&schema.UserTableInfo},
			`SELECT ` + schema.UserTableInfo.AllColumns() + ` 
FROM trustyca.user 
WHERE id = $1`,
		},
		{
			query.GetRowByColumn, []any{&schema.UserTableInfo, "email"},
			`SELECT ` + schema.UserTableInfo.AllColumns() + ` 
FROM trustyca.user 
WHERE email = $1`,
		},
		{
			query.ListAllColumns, []any{&schema.UserTableInfo},
			`SELECT ` + schema.UserTableInfo.AllColumns() + ` 
FROM trustyca.user 
ORDER BY id ASC 
LIMIT $1 
OFFSET $2`,
		},
		{
			query.ListAllColumns, []any{&schema.LoginTableInfo},
			`SELECT ` + schema.LoginTableInfo.AllColumns() + ` 
FROM trustyca.login 
ORDER BY id ASC 
LIMIT $1 
OFFSET $2`,
		},
		{
			query.DeleteRowByID, []any{&schema.LoginTableInfo},
			`DELETE FROM trustyca.login 
WHERE id = $1`,
		},
	})
}
