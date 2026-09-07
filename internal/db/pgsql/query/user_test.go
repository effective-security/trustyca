package query_test

import (
	"testing"

	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/internal/db/schema"
)

func Test_UserQueries(t *testing.T) {
	t.Parallel()

	check(t, []tcase{
		{
			query.RegisterLogin, nil,
			`INSERT INTO trustyca.login 
( ` + schema.LoginTableInfo.AllColumns() + ` 
) VALUES ( $1, $2, $3, $4, $5, $6, $7, $8, $9, 1, Now() 
) 
ON CONFLICT (provider,email) DO UPDATE SET 
	email_verified=EXCLUDED.email_verified,
	name=EXCLUDED.name,
	access_token=EXCLUDED.access_token,
	refresh_token=EXCLUDED.refresh_token,
	token_expires_at=EXCLUDED.token_expires_at,
	count = login.count + 1,
	last_at=Now() 
RETURNING ` + schema.LoginTableInfo.AllColumns(),
		},
		{
			query.RegisterUser, nil,
			`INSERT INTO trustyca.user 
( id, email, email_verified, name 
) VALUES ( $1, $2, $3, $4 
) 
ON CONFLICT (email) DO UPDATE SET name=EXCLUDED.name 
RETURNING ` + schema.UserTableInfo.AllColumns(),
		},
		{
			query.UpdateUser, nil,
			`UPDATE trustyca.user 
SET name=$1, email_verified=$2 
WHERE id = $3 
RETURNING ` + schema.UserTableInfo.AllColumns(),
		},
		{
			query.GetUserBy, []any{schema.User.ID.Name},
			`SELECT ` + schema.UserTableInfo.AllColumns() + ` 
FROM trustyca.user 
WHERE id = $1`,
		},
		{
			query.GetUserBy, []any{schema.User.Email.Name},
			`SELECT ` + schema.UserTableInfo.AllColumns() + ` 
FROM trustyca.user 
WHERE email = $1`,
		},
		{
			query.GetLoginBy, []any{schema.Login.ID.Name},
			`SELECT ` + schema.LoginTableInfo.AllColumns() + ` 
FROM trustyca.login 
WHERE id = $1`,
		},
		{
			query.GetLoginBy, []any{schema.Login.Email.Name},
			`SELECT ` + schema.LoginTableInfo.AllColumns() + ` 
FROM trustyca.login 
WHERE email = $1`,
		},
	})
}
