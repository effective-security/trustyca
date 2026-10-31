package orgs

import (
	"cmp"
	"context"

	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/authctx"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/internal/events"
	"google.golang.org/grpc/codes"
)

// ListEvents returns the audit events of the org selected in the token,
// newest first and paged by cursor: every event of the org for a caller
// with an org-wide role or an org-wide API key, the org-wide events and
// those of the caller's projects for a member with project grants only, and
// the events of one project when the request names it (the interceptor
// authorized the caller's role in it) or when an API key is restricted to
// it. A project of another org or an inactive project is not found.
func (s *Service) ListEvents(ctx context.Context, req *pb.ListEventsRequest) (*pb.EventsResponse, error) {
	orgID, err := tokenOrg(ctx)
	if err != nil {
		return nil, err
	}
	projectID, err := parseOptionalID(ctx, req.ProjectID, "project ID")
	if err != nil {
		return nil, err
	}
	tctx := authctx.FromContext(ctx)
	if keyProject := tctx.ProjectID(); tctx.IsAPIKey() && !keyProject.IsZero() {
		// a restricted key lists the events of its project only
		if !projectID.IsZero() && projectID.UInt64() != keyProject.UInt64() {
			return nil, httperror.NewGrpcFromCtx(ctx, codes.NotFound, "project not found")
		}
		projectID = keyProject
	}
	_, err = s.getProject(ctx, orgID, projectID)
	if err != nil {
		return nil, err
	}
	after, before, err := events.ParseTimeRange(req.After, req.Before)
	if err != nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "%s", err.Error())
	}
	// the list pages by cursor only: an empty cursor is the first page
	cursor, err := query.ListCursor(ctx, cmp.Or(req.Cursor, query.InitialCursor), query.ParseTimeCursor)
	if err != nil {
		return nil, err
	}
	q := &query.ListEventsRequest{
		OrgID:     orgID.UInt64(),
		ProjectID: projectID.UInt64(),
		Type:      req.Type,
		After:     after,
		Before:    before,
		Limit:     query.Limit(req.Limit),
		Cursor:    cursor,
	}
	if projectID.IsZero() && !tctx.IsAPIKey() {
		grants, err := s.authorizer.Grants(ctx, orgID, tctx.UserID())
		if err != nil {
			return nil, httperror.WrapWithCtx(ctx, err, "failed to resolve access")
		}
		if !grants.CanListAllProjects() {
			// a member with project grants only sees the org-wide events
			// and those of its projects; a user without a grant sees none
			ids := grants.GrantedProjectIDs()
			if len(ids) == 0 {
				return &pb.EventsResponse{}, nil
			}
			q.ProjectIDs = ids
		}
	}
	res, err := s.db.ListEvents(ctx, q)
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "failed to list events")
	}
	return res.Pb(), nil
}
