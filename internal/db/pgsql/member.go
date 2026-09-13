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
)

// AddMember grants a role org-wide (empty ProjectID) or in a project.
// An existing grant at the same scope gets the new role.
func (p *Provider) AddMember(ctx context.Context, member *model.Membership) (*model.Membership, error) {
	id := member.ID
	if id.UInt64() == 0 {
		id = p.NextID()
	}

	err := xdb.Validate(member)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	q, name := query.AddMember()
	defer DbMeasureQuerySince(name, time.Now())

	res, err := xdb.QueryRow[model.Membership](ctx, p,
		q,
		id.UInt64(),
		member.OrgID,
		member.ProjectID,
		member.UserID,
		member.Role,
	)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// UpdateMemberRole updates the role of a grant at the given scope
func (p *Provider) UpdateMemberRole(ctx context.Context, req *query.UpdateMemberRoleRequest) (*model.Membership, error) {
	if req.OrgID == 0 || req.UserID == 0 || req.Role == 0 {
		return nil, errors.New("orgID, userID and role are required")
	}
	qp := req.QueryParams()
	q, name := query.UpdateMemberRole(qp)
	defer DbMeasureQuerySince(name, time.Now())

	res, err := xdb.QueryRow[model.Membership](ctx, p, q, qp.Args()...)
	if err != nil {
		return nil, xdb.CheckNotFoundError(err, schema.MembershipTableInfo.Name,
			fmt.Sprintf("%d/%d/%d", req.OrgID, req.ProjectID, req.UserID))
	}
	return res, nil
}

// GetUserMemberships returns all grants of a user in active orgs
func (p *Provider) GetUserMemberships(ctx context.Context, userID uint64) (model.MembershipInfoSlice, error) {
	return p.ListMemberships(ctx, &query.ListMembershipsRequest{
		UserID:    userID,
		OrgStatus: pb.ItemStatus_Active,
	})
}

// ListMemberships lists memberships
func (p *Provider) ListMemberships(ctx context.Context, req *query.ListMembershipsRequest) (model.MembershipInfoSlice, error) {
	qp := req.QueryParams()
	q, name := query.ListMemberships(qp)
	defer DbMeasureQuerySince(name, time.Now())

	var rs model.MembershipInfoResult
	err := xdb.ExecuteQuery(ctx, p.DB(), &rs, q, qp.Args()...)
	if err != nil {
		return nil, err
	}
	return rs.Rows, nil
}

// DeleteMember deletes grants at the requested scope
func (p *Provider) DeleteMember(ctx context.Context, r *query.DeleteMemberRequest) (int64, error) {
	if r.OrgID == 0 && r.UserID == 0 {
		return 0, errors.New("orgID or userID is required")
	}
	qp := r.QueryParams()
	q, name := query.DeleteMember(qp)
	defer DbMeasureQuerySince(name, time.Now())

	res, err := p.ExecContext(ctx, q, qp.Args()...)
	if err != nil {
		return 0, errors.WithStack(err)
	}
	return res.RowsAffected()
}
