package pgsql

import (
	"context"
	"fmt"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/internal/db/schema"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/certutil"
)

// RegisterOrg registers a new org
func (p *Provider) RegisterOrg(ctx context.Context, m *model.Org, ownerID uint64) (*model.Org, error) {
	org := *m
	if org.ID.UInt64() == 0 {
		org.ID = p.NextID()
	}
	if org.Alias == "" {
		org.Alias = "cp_" + certutil.RandomString(29)
	}

	err := xdb.Validate(&org)
	if err != nil {
		return nil, errors.WithStack(err)
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

	q, name := query.RegisterOrg()
	defer DbMeasureQuerySince(name, time.Now())

	res, err := xdb.QueryRow[model.Org](ctx, p,
		q,
		org.ID,
		org.Alias,
		org.Name,
		org.Description,
	)
	if err != nil {
		p.CheckErrIDConflict(ctx, err, org.ID.UInt64())
		return nil, err
	}

	if ownerID != 0 {
		_, err = tx.(*Provider).AddMember(ctx, &model.Membership{
			OrgID:  res.ID,
			UserID: xdb.NewID(ownerID),
			Role:   pb.Role_Owner,
		})
		if err != nil {
			return nil, errors.WithMessage(err, "unable to add owner")
		}
	}

	err = tx.Commit()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return res, nil
}

// UpdateOrg updates an org's name and description
func (p *Provider) UpdateOrg(ctx context.Context, req *query.UpdateOrgRequest) (*model.Org, error) {
	if req.Name == "" && req.Description == "" && req.Status == pb.ItemStatus_Unknown {
		return nil, errors.New("no changes to update")
	}
	if req.Name != "" && len(req.Name) > 64 {
		return nil, errors.Errorf("invalid name: %q", req.Name)
	}

	qp := req.QueryParams()
	q, qname := query.UpdateOrg(qp)
	defer DbMeasureQuerySince(qname, time.Now())

	res, err := xdb.QueryRow[model.Org](ctx, p, q, qp.Args()...)
	if err != nil {
		return nil, xdb.CheckNotFoundError(err, schema.OrgTableInfo.Name, req.ID)
	}
	return res, nil
}

// ListOrgs lists orgs
func (p *Provider) ListOrgs(ctx context.Context, req *query.ListOrgsRequest) (*model.OrgResult, error) {
	qp := req.QueryParams()
	q, name := query.ListOrgs(qp)
	defer DbMeasureQuerySince(name, time.Now())

	var rs model.OrgResult
	err := xdb.ExecuteQuery(ctx, p, &rs, q, qp)
	if err != nil {
		return nil, err
	}
	return &rs, nil
}

// GetOrg returns Org by ID
func (p *Provider) GetOrg(ctx context.Context, id uint64) (*model.Org, error) {
	q, name := query.GetRowByID(&schema.OrgTableInfo, id)
	defer DbMeasureQuerySince(name, time.Now())

	res, err := xdb.QueryRow[model.Org](ctx, p, q, id)
	if err != nil {
		return nil, xdb.CheckNotFoundError(err, schema.OrgTableInfo.Name, id)
	}
	return res, nil
}

// FindOrg returns Org by alias
func (p *Provider) FindOrg(ctx context.Context, alias string) (*model.Org, error) {
	q, name := query.GetRowByColumn(&schema.OrgTableInfo, schema.Org.Alias.Name)
	defer DbMeasureQuerySince(name, time.Now())

	res, err := xdb.QueryRow[model.Org](ctx, p, q, alias)
	if err != nil {
		return nil, xdb.CheckNotFoundError(err, schema.OrgTableInfo.Name, alias)
	}
	return res, nil
}

// GetUserOrgs gets the orgs for a user
func (p *Provider) GetUserOrgs(ctx context.Context, userID uint64) (model.OrgSlice, error) {
	q, name := query.GetUserOrgs(userID)
	defer DbMeasureQuerySince(name, time.Now())

	var rs model.OrgResult
	err := xdb.ExecuteQuery(ctx, p.DB(), &rs, q, userID)
	if err != nil {
		return nil, err
	}
	// a user with an org-wide grant and project grants in the same org
	// produces one row per grant; return each org once
	seen := map[uint64]bool{}
	orgs := make(model.OrgSlice, 0, len(rs.Rows))
	for _, o := range rs.Rows {
		if !seen[o.ID.UInt64()] {
			seen[o.ID.UInt64()] = true
			orgs = append(orgs, o)
		}
	}
	return orgs, nil
}

// DeleteOrg deletes an org and all its members
func (p *Provider) DeleteOrg(ctx context.Context, id uint64) (map[string]int64, error) {
	defer DbMeasureSince(time.Now())
	counts := map[string]int64{}

	tables := []string{
		schema.EventTableInfo.SchemaName,
		schema.InviteTableInfo.SchemaName,
		schema.MembershipTableInfo.SchemaName,
		schema.ProjectTableInfo.SchemaName,
	}
	for _, table := range tables {
		res, err := p.ExecContext(ctx, fmt.Sprintf("DELETE FROM %s WHERE org_id=$1;", table), id)
		if err != nil {
			return counts, errors.WithStack(err)
		}
		rows, err := res.RowsAffected()
		if err != nil {
			return counts, errors.WithStack(err)
		}
		counts[table] = rows
	}

	res, err := p.ExecContext(ctx, fmt.Sprintf("DELETE FROM %s WHERE id=$1;", schema.OrgTableInfo.Name), id)
	if err != nil {
		return counts, errors.WithStack(err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return counts, errors.WithStack(err)
	}
	counts[schema.OrgTableInfo.Name] = rows
	return counts, nil
}
