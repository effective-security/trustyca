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

// AddMember adds a member to an org
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
		member.UserID,
		member.Role,
	)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// UpdateMemberRole updates the role of a member in an org
func (p *Provider) UpdateMemberRole(ctx context.Context, orgID, userID uint64, role pb.Role_Enum) (*model.Membership, error) {
	q, name := query.UpdateMemberRole()
	defer DbMeasureQuerySince(name, time.Now())

	res, err := xdb.QueryRow[model.Membership](ctx, p,
		q,
		role,
		orgID,
		userID,
	)
	if err != nil {
		return nil, xdb.CheckNotFoundError(err, schema.MembershipTableInfo.Name, fmt.Sprintf("%d/%d", orgID, userID))
	}
	return res, nil
}

// GetUserMemberships gets the memberships for a user
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

// DeleteMember deletes a member from an org
func (p *Provider) DeleteMember(ctx context.Context, r *query.DeleteMemberRequest) (int64, error) {
	if r.OrgID == 0 && r.UserID == 0 {
		return 0, errors.New("orgID or userID is required")
	}
	qp := r.QueryParams()
	q, name := query.DeleteMember(r.QueryParams())
	defer DbMeasureQuerySince(name, time.Now())

	res, err := p.ExecContext(ctx, q, qp.Args()...)
	if err != nil {
		return 0, errors.WithStack(err)
	}
	return res.RowsAffected()
}
