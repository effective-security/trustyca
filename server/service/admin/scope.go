package admin

import (
	"context"
	"time"

	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/xdb"
	"google.golang.org/grpc/codes"
)

// listScope is the org scope of a support list across orgs: the org the
// request names, with its project when it names one; the platform rows
// when it names no org and asks for them; else every org and the platform
type listScope struct {
	orgID     uint64
	projectID uint64
	platform  bool
	allOrgs   bool
}

// parseListScope parses the scope of a support list. A project is accepted
// with an org only, since project IDs are unique per org.
func parseListScope(ctx context.Context, orgIDVal, projectIDVal string, platform bool) (listScope, error) {
	var res listScope
	if orgIDVal != "" {
		orgID, err := xdb.ParseID(orgIDVal)
		if err != nil {
			return res, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid org ID")
		}
		res.orgID = orgID.UInt64()
	}
	if projectIDVal != "" {
		if res.orgID == 0 {
			return res, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "org ID is required with a project ID")
		}
		projectID, err := xdb.ParseID(projectIDVal)
		if err != nil {
			return res, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid project ID")
		}
		res.projectID = projectID.UInt64()
	}
	if res.orgID == 0 {
		res.platform = platform
		res.allOrgs = !platform
	}
	return res, nil
}

// parseIDs parses the IDs of a list filter; an empty list is no filter
func parseIDs(ctx context.Context, vals []string, what string) ([]uint64, error) {
	if len(vals) == 0 {
		return nil, nil
	}
	ids := make([]uint64, 0, len(vals))
	for _, val := range vals {
		id, err := xdb.ParseID(val)
		if err != nil {
			return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid %s: %s", what, val)
		}
		ids = append(ids, id.UInt64())
	}
	return ids, nil
}

// parseTime parses an optional RFC3339 time of a request
func parseTime(ctx context.Context, val, what string) (*time.Time, error) {
	if val == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, val)
	if err != nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid %s: RFC3339 time expected", what)
	}
	t = t.UTC()
	return &t, nil
}
