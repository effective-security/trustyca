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
	"github.com/effective-security/xdb"
	"github.com/effective-security/xlog"
)

// DefaultInviteExpiry is the validity of an invite when the caller does not
// set ExpiresAt
const DefaultInviteExpiry = 14 * 24 * time.Hour

// CreateInvite creates or updates an invite for a user to join an org
// (empty ProjectID) or a project
func (p *Provider) CreateInvite(ctx context.Context, invite *model.Invite) (*model.Invite, error) {
	id := invite.ID
	if id.UInt64() == 0 {
		id = p.NextID()
	}

	inv := *invite
	inv.Email = strings.ToLower(inv.Email)
	if inv.ExpiresAt.IsZero() {
		inv.ExpiresAt = xdb.Time(time.Now().Add(DefaultInviteExpiry))
	}

	err := xdb.Validate(&inv)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	q, name := query.CreateInvite()
	defer DbMeasureQuerySince(name, time.Now())

	res, err := xdb.QueryRow[model.Invite](ctx, p,
		q,
		id.UInt64(),
		inv.OrgID,
		inv.ProjectID,
		inv.InviterID,
		inv.Email,
		inv.Role,
		inv.ExpiresAt,
	)
	if err != nil {
		p.CheckErrIDConflict(ctx, err, id.UInt64())
		return nil, err
	}
	return res, nil
}

// GetInvite returns an invite by ID
func (p *Provider) GetInvite(ctx context.Context, id uint64) (*model.Invite, error) {
	q, name := query.GetRowByID(&schema.InviteTableInfo)
	defer DbMeasureQuerySince(name, time.Now())

	res, err := xdb.QueryRow[model.Invite](ctx, p, q, id)
	if err != nil {
		return nil, xdb.CheckNotFoundError(err, schema.InviteTableInfo.Name, id)
	}
	return res, nil
}

// GetInviteByOrgAndEmail returns an invite by org, scope and email.
// projectID 0 returns the Org scope invite.
func (p *Provider) GetInviteByOrgAndEmail(ctx context.Context, orgID, projectID uint64, email string) (*model.Invite, error) {
	req := &query.GetInviteRequest{
		OrgID:     orgID,
		ProjectID: projectID,
		Email:     strings.ToLower(email),
	}
	qp := req.QueryParams()
	q, name := query.GetInvite(qp)
	defer DbMeasureQuerySince(name, time.Now())

	res, err := xdb.QueryRow[model.Invite](ctx, p, q, qp.Args()...)
	if err != nil {
		return nil, xdb.CheckNotFoundError(err, schema.InviteTableInfo.Name, fmt.Sprintf("%d/%d/%s", orgID, projectID, req.Email))
	}
	return res, nil
}

// GetOrgInvites returns invites of all scopes for an org
func (p *Provider) GetOrgInvites(ctx context.Context, orgID uint64) (model.InviteSlice, error) {
	q, name := query.GetOrgInvites()
	defer DbMeasureQuerySince(name, time.Now())

	var rs model.InviteResult
	err := xdb.ExecuteQuery(ctx, p.DB(), &rs, q, orgID)
	if err != nil {
		return nil, err
	}
	return rs.Rows, nil
}

// GetUserInvites returns invites for a user's email
func (p *Provider) GetUserInvites(ctx context.Context, email string) (model.InviteSlice, error) {
	q, name := query.GetUserInvites()
	defer DbMeasureQuerySince(name, time.Now())

	email = strings.ToLower(email)
	var rs model.InviteResult
	err := xdb.ExecuteQuery(ctx, p.DB(), &rs, q, email)
	if err != nil {
		return nil, err
	}
	return rs.Rows, nil
}

// DeleteInviteByID deletes an invite by ID
func (p *Provider) DeleteInviteByID(ctx context.Context, id uint64) (int64, error) {
	q, name := query.DeleteRowByID(&schema.InviteTableInfo)
	defer DbMeasureQuerySince(name, time.Now())

	res, err := p.ExecContext(ctx, q, id)
	if err != nil {
		return 0, errors.WithStack(err)
	}
	return res.RowsAffected()
}

// DeleteInvite deletes invites at the requested scope
func (p *Provider) DeleteInvite(ctx context.Context, r *query.DeleteInviteRequest) (int64, error) {
	if r.OrgID == 0 && r.Email == "" {
		return 0, errors.New("orgID or email is required")
	}
	req := *r
	req.Email = strings.ToLower(req.Email)
	qp := req.QueryParams()
	q, name := query.DeleteInvite(qp)
	defer DbMeasureQuerySince(name, time.Now())

	res, err := p.ExecContext(ctx, q, qp.Args()...)
	if err != nil {
		return 0, errors.WithStack(err)
	}
	return res.RowsAffected()
}

// AcceptInvite accepts an invite for a user, adds the user as a member at
// the invite's scope with the invited role, and removes the invite.
func (p *Provider) AcceptInvite(ctx context.Context, inviteID, userID uint64) (*model.Membership, error) {
	defer DbMeasureSince(time.Now())

	invite, err := p.GetInvite(ctx, inviteID)
	if err != nil {
		return nil, err
	}

	user, err := p.GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	if !strings.EqualFold(user.Email, invite.Email) {
		return nil, errors.Errorf("invite email does not match user email")
	}
	if invite.IsExpired(time.Now()) {
		return nil, errors.Errorf("invite expired")
	}

	tx, err := p.BeginTx(ctx, nil)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer func() {
		err := tx.Close()
		if err != nil {
			logger.ContextKV(ctx, xlog.ERROR, "reason", "close", "err", err.Error())
		}
	}()

	txProvider := tx.(*Provider)
	membership, err := txProvider.AddMember(ctx, &model.Membership{
		OrgID:     invite.OrgID,
		ProjectID: invite.ProjectID,
		UserID:    user.ID,
		Role:      invite.Role,
	})
	if err != nil {
		return nil, errors.WithMessage(err, "unable to add member")
	}

	_, err = txProvider.DeleteInviteByID(ctx, invite.ID.UInt64())
	if err != nil {
		return nil, errors.WithMessage(err, "unable to delete invite")
	}

	err = tx.Commit()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return membership, nil
}

// AcceptInvites moves invites to memberships at the invites' scopes
func (p *Provider) AcceptInvites(ctx context.Context, user *model.User) (int64, error) {
	invites, err := p.GetUserInvites(ctx, user.Email)
	if err != nil {
		return 0, err
	}
	logger.ContextKV(ctx, xlog.TRACE,
		"user_id", user.ID,
		"email", user.Email,
		"invites", len(invites))

	for _, inv := range invites {
		_, err = p.AddMember(ctx, &model.Membership{
			OrgID:     inv.OrgID,
			ProjectID: inv.ProjectID,
			UserID:    user.ID,
			Role:      inv.Role,
		})
		if err != nil {
			logger.ContextKV(ctx, xlog.ERROR, "role", inv.Role, "user", user.ID.UnderscoreString(), "err", err.Error())
			continue
		}
		_, err = p.DeleteInviteByID(ctx, inv.ID.UInt64())
		if err != nil {
			logger.ContextKV(ctx, xlog.ERROR, "role", inv.Role, "user", user.ID.UnderscoreString(), "err", err.Error())
			continue
		}
	}
	return int64(len(invites)), nil
}
