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

// RegisterProfile creates a certificate profile, or replaces the issuer
// label, status and config of the profile with the same label in the same
// scope; the row ID and creation time of a replaced profile are kept
func (p *Provider) RegisterProfile(ctx context.Context, m *model.CertificateProfile) (*model.CertificateProfile, error) {
	im := *m
	if im.ID.IsZero() {
		im.ID = p.NextID()
	}
	if im.Status == pb.ItemStatus_Unknown {
		im.Status = pb.ItemStatus_Active
	}

	err := xdb.Validate(&im)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	q, name := query.RegisterProfile()
	defer DbMeasureQuerySince(name, time.Now())

	res, err := xdb.QueryRow[model.CertificateProfile](ctx, p, q,
		im.ID,
		im.OrgID,
		im.ProjectID,
		im.Label,
		im.IssuerLabel,
		im.Status,
		im.Config,
	)
	if err != nil {
		p.CheckErrIDConflict(ctx, err, im.ID.UInt64())
		return nil, err
	}
	return res, nil
}

// GetProfile returns a certificate profile by ID
func (p *Provider) GetProfile(ctx context.Context, id uint64) (*model.CertificateProfile, error) {
	q, name := query.GetRowByID(&schema.CertificateProfileTableInfo)
	defer DbMeasureQuerySince(name, time.Now())

	res, err := xdb.QueryRow[model.CertificateProfile](ctx, p, q, id)
	if err != nil {
		return nil, xdb.CheckNotFoundError(err, schema.CertificateProfileTableInfo.Name, id)
	}
	return res, nil
}

// FindProfile returns the profile of the exact scope and label: a zero
// orgID is the platform scope and a zero projectID the org scope. The
// resolution of a label through the scopes is the caller's.
func (p *Provider) FindProfile(ctx context.Context, orgID, projectID uint64, label string) (*model.CertificateProfile, error) {
	req := &query.FindProfileRequest{
		OrgID:     orgID,
		ProjectID: projectID,
		Label:     label,
	}
	qp := req.QueryParams()
	q, name := query.FindProfile(qp)
	defer DbMeasureQuerySince(name, time.Now())

	res, err := xdb.QueryRow[model.CertificateProfile](ctx, p, q, qp.Args()...)
	if err != nil {
		return nil, xdb.CheckNotFoundError(err, schema.CertificateProfileTableInfo.Name, fmt.Sprintf("%d/%d/%s", orgID, projectID, label))
	}
	return res, nil
}

// ListProfiles lists certificate profiles, newest first; the request names
// its org scope
func (p *Provider) ListProfiles(ctx context.Context, req *query.ListProfilesRequest) (*model.CertificateProfileResult, error) {
	err := xdb.Validate(req)
	if err != nil {
		return nil, err
	}
	qp := req.QueryParams()
	q, name := query.ListProfiles(qp)
	defer DbMeasureQuerySince(name, time.Now())

	var rs model.CertificateProfileResult
	err = listRows(ctx, p, req.Cursor, profileCursor, &rs, q, qp)
	if err != nil {
		return nil, err
	}
	return &rs, nil
}

// profileCursor returns the cursor of the page after the row
func profileCursor(last *model.CertificateProfile) string {
	return query.EncodeCursor(last.ID)
}

// DeleteProfile deletes a certificate profile of the exact org scope (a zero
// orgID is the platform) and returns the number of deleted rows
func (p *Provider) DeleteProfile(ctx context.Context, orgID, id uint64) (int64, error) {
	q, name := query.DeleteRowByOrgAndID(&schema.CertificateProfileTableInfo)
	defer DbMeasureQuerySince(name, time.Now())

	res, err := p.ExecContext(ctx, q, query.OrgArg(orgID), id)
	if err != nil {
		return 0, errors.WithStack(err)
	}
	return res.RowsAffected()
}
