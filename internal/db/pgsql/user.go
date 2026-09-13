package pgsql

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/internal/db/schema"
	"github.com/effective-security/x/values"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xlog"
)

// LoginUser returns logged in model.User
func (p *Provider) LoginUser(ctx context.Context, m *model.Login) (*model.Login, *model.User, error) {
	id := p.NextID()

	login := m
	login.Email = strings.ToLower(login.Email)
	login.Name = values.StringsCoalesce(login.Name, login.Email)

	err := xdb.Validate(login)
	if err != nil {
		return nil, nil, err
	}

	q, name := query.RegisterLogin()
	defer DbMeasureQuerySince(name, time.Now())

	logger.KV(xlog.DEBUG,
		"provider", login.Provider,
		"email", login.Email,
		"extID", login.ExternalID,
	)

	l, err := xdb.QueryRow[model.Login](ctx, p,
		q,
		id.UInt64(),
		login.ExternalID,
		login.Provider,
		login.Email,
		login.EmailVerified,
		login.Name,
		login.AccessToken,
		login.RefreshToken,
		login.TokenExpiresAt,
	)
	if err != nil {
		p.CheckErrIDConflict(ctx, err, id.UInt64())
		return nil, nil, err
	}

	q2, _ := query.RegisterUser()
	user, err := xdb.QueryRow[model.User](ctx, p,
		q2,
		id.UInt64(),
		login.Email,
		login.EmailVerified,
		login.Name,
	)
	if err != nil {
		p.CheckErrIDConflict(ctx, err, id.UInt64())
		return nil, nil, xdb.CheckNotFoundError(err, schema.LoginTableInfo.Name, id.UInt64())
	}

	return l, user, nil
}

// DeleteUserByEmail deletes user and logins
func (p *Provider) DeleteUserByEmail(ctx context.Context, email string) (map[string]int64, error) {
	defer DbMeasureQuerySince("DeleteUserByEmail", time.Now())

	email = strings.ToLower(email)
	counts := map[string]int64{}
	tables := []string{
		schema.LoginTableInfo.SchemaName,
		schema.UserTableInfo.SchemaName,
	}
	for _, table := range tables {
		res, err := p.ExecContext(ctx, fmt.Sprintf("DELETE FROM %s WHERE email=$1;", table), email)
		if err != nil {
			return counts, errors.WithStack(err)
		}
		rows, err := res.RowsAffected()
		if err != nil {
			return counts, errors.WithStack(err)
		}
		counts[table] = rows
	}

	return counts, nil
}

// DeleteUser deletes user and logins by user ID
func (p *Provider) DeleteUser(ctx context.Context, id uint64) (map[string]int64, error) {
	user, err := p.GetUser(ctx, id)
	if err != nil {
		return nil, err
	}
	return p.DeleteUserByEmail(ctx, user.Email)
}

// UpdateUser updates a user's profile
func (p *Provider) UpdateUser(ctx context.Context, id uint64, name string, emailVerified bool) (*model.User, error) {
	if name == "" || len(name) > xdb.MaxLenForName {
		return nil, errors.Errorf("invalid name: %q", name)
	}

	q, qname := query.UpdateUser()
	defer DbMeasureQuerySince(qname, time.Now())

	res, err := xdb.QueryRow[model.User](ctx, p, q, name, emailVerified, id)
	if err != nil {
		return nil, xdb.CheckNotFoundError(err, schema.UserTableInfo.Name, id)
	}
	return res, nil
}

// GetLogin returns a login by ID
func (p *Provider) GetLogin(ctx context.Context, id uint64) (*model.Login, error) {
	q, name := query.GetLoginBy(schema.Login.ID.Name)
	defer DbMeasureQuerySince(name, time.Now())

	res, err := xdb.QueryRow[model.Login](ctx, p, q, id)
	if err != nil {
		return nil, xdb.CheckNotFoundError(err, schema.LoginTableInfo.Name, id)
	}
	return res, nil
}

// DeleteLogin deletes a single login by ID
func (p *Provider) DeleteLogin(ctx context.Context, id uint64) (int64, error) {
	q, name := query.DeleteRowByID(&schema.LoginTableInfo)
	defer DbMeasureQuerySince(name, time.Now())

	res, err := p.ExecContext(ctx, q, id)
	if err != nil {
		return 0, errors.WithStack(err)
	}
	return res.RowsAffected()
}

// GetUser returns user
func (p *Provider) GetUser(ctx context.Context, id uint64) (*model.User, error) {
	q, name := query.GetUserBy(schema.User.ID.Name)
	defer DbMeasureQuerySince(name, time.Now())

	res, err := xdb.QueryRow[model.User](ctx, p, q, id)
	if err != nil {
		return nil, xdb.CheckNotFoundError(err, "user", id)
	}

	return res, nil
}

// GetUserByEmail returns User
func (p *Provider) GetUserByEmail(ctx context.Context, email string) (*model.User, error) {
	q, name := query.GetUserBy(schema.User.Email.Name)
	defer DbMeasureQuerySince(name, time.Now())

	email = strings.ToLower(email)
	res, err := xdb.QueryRow[model.User](ctx, p, q, email)
	if err != nil {
		return nil, xdb.CheckNotFoundError(err, "user", email)
	}

	return res, nil
}

// GetLoginsByEmail returns Logins
func (p *Provider) GetLoginsByEmail(ctx context.Context, email string) (model.LoginSlice, error) {
	q, name := query.GetLoginBy(schema.Login.Email.Name)
	defer DbMeasureQuerySince(name, time.Now())

	email = strings.ToLower(email)
	var rs model.LoginResult
	err := xdb.ExecuteQuery(ctx, p.DB(), &rs, q, email)
	if err != nil {
		return nil, err
	}
	return rs.Rows, nil
}

// ListLogins returns Logins
func (p *Provider) ListLogins(ctx context.Context, limit, offset uint32) (model.LoginSlice, uint32, error) {
	limit = values.NumbersCoalesce(limit, xdb.DefaultPageSize)
	q, name := query.ListAllColumns(&schema.LoginTableInfo)
	defer DbMeasureQuerySince(name, time.Now())

	var rs model.LoginResult
	err := xdb.ExecuteQueryWithPagination(ctx, p.DB(), &rs, q, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	return rs.Rows, rs.NextOffset, nil
}
