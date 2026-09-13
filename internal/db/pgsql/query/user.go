package query

import (
	"github.com/effective-security/trustyca/internal/db/schema"
	"github.com/effective-security/xdb/xsql"
)

// RegisterLogin returns SQL query to register a login
func RegisterLogin(args ...any) (string, string) {
	const key = "RegisterLogin"
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		q := schema.LoginTableInfo.InsertInto().
			Clause(`ON CONFLICT (provider,email) DO UPDATE SET 
	email_verified=EXCLUDED.email_verified,
	name=EXCLUDED.name,
	access_token=EXCLUDED.access_token,
	refresh_token=EXCLUDED.refresh_token,
	token_expires_at=EXCLUDED.token_expires_at,
	count = ` + schema.LoginTableInfo.Name + `.count + 1,
	last_at=Now()`).
			Returning(schema.LoginTableInfo.AllColumns())
		// set all columns to nil as placeholders
		q.NewRow().
			Set(schema.Login.ID.Name, nil).
			Set(schema.Login.ExternalID.Name, nil).
			Set(schema.Login.Provider.Name, nil).
			Set(schema.Login.Email.Name, nil).
			Set(schema.Login.EmailVerified.Name, nil).
			Set(schema.Login.Name.Name, nil).
			Set(schema.Login.AccessToken.Name, nil).
			Set(schema.Login.RefreshToken.Name, nil).
			Set(schema.Login.TokenExpiresAt.Name, nil).
			SetExpr(schema.Login.Count.Name, "1").
			SetExpr(schema.Login.LastAt.Name, "Now()")
		return q
	})
}

// RegisterUser returns SQL query to register a user
func RegisterUser(args ...any) (string, string) {
	const key = "RegisterUser"
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		q := schema.UserTableInfo.InsertInto().
			Clause(`ON CONFLICT (email) DO UPDATE SET name=EXCLUDED.name`).
			Returning(schema.UserTableInfo.AllColumns())

		// set all columns to nil as placeholders
		q.NewRow().
			Set(schema.User.ID.Name, nil).
			Set(schema.User.Email.Name, nil).
			Set(schema.User.EmailVerified.Name, nil).
			Set(schema.User.Name.Name, nil)
		return q
	})
}

// UpdateUser returns SQL query to update a user's name and email_verified flag
func UpdateUser(args ...any) (string, string) {
	const key = "UpdateUser"
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		return schema.UserTableInfo.
			Update().
			Set(schema.User.Name.Name, nil).
			Set(schema.User.EmailVerified.Name, nil).
			Where(schema.User.ID.Name+" = ?", nil).
			Returning(schema.UserTableInfo.AllColumns())
	})
}

// GetUserBy returns SQL query with where clause by column name
func GetUserBy(args ...any) (string, string) {
	var whereColumn string
	if len(args) > 0 {
		whereColumn = args[0].(string)
	}
	key := "GetUserBy" + whereColumn
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		q := schema.UserTableInfo.Select()
		if whereColumn != "" {
			q.Where(whereColumn + " = $1")
		}
		return q
	})
}

// GetLoginBy returns SQL query with where clause by column name
func GetLoginBy(args ...any) (string, string) {
	var whereColumn string
	if len(args) > 0 {
		whereColumn = args[0].(string)
	}
	key := "GetLoginBy" + whereColumn
	return xsql.Postgres.GetOrCreateQuery(key, func(name string) xsql.Builder {
		q := schema.Login.Table.Select()
		if whereColumn != "" {
			q.Where(whereColumn + " = $1")
		}
		return q
	})
}
