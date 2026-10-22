package ca

import (
	"cmp"
	"context"
	"net/http"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/authctx"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/xdb"
	"google.golang.org/grpc/codes"
)

// tenantOrg returns the org of a tenant request. A user or API key token
// carries the selected org, and an explicit OrgID in the request must match
// it. A trusted service caller (RA, CIS, jobs over mTLS) has no org in its
// token and names the org explicitly; the org must exist and be active.
func (s *Service) tenantOrg(ctx context.Context, reqOrgID string) (xdb.ID, error) {
	tctx := authctx.FromContext(ctx)
	orgID := tctx.OrgID()
	if !orgID.IsZero() {
		if reqOrgID != "" && reqOrgID != orgID.String() {
			return xdb.ID(0), httperror.NewGrpcFromCtx(ctx, codes.PermissionDenied, "org mismatch")
		}
		return orgID, nil
	}
	if !strings.HasPrefix(tctx.AppRole(), authctx.ServiceRolePrefix) {
		return xdb.ID(0), httperror.NewGrpcFromCtx(ctx, codes.PermissionDenied, "org not selected")
	}
	if reqOrgID == "" {
		return xdb.ID(0), httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "org ID is required")
	}
	orgID, err := xdb.ParseID(reqOrgID)
	if err != nil {
		return xdb.ID(0), httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid org ID")
	}
	org, err := s.orgs.GetOrg(ctx, orgID.UInt64())
	if err != nil {
		if xdb.IsNotFoundError(err) {
			return xdb.ID(0), httperror.NewGrpcFromCtx(ctx, codes.NotFound, "org not found")
		}
		return xdb.ID(0), httperror.WrapWithCtx(ctx, err, "unable to find org")
	}
	if org.Status != pb.ItemStatus_Active {
		return xdb.ID(0), preconditionFailed(ctx, "org is deleted")
	}
	return orgID, nil
}

// tenantProject returns the project of a tenant request, or a zero ID for
// the org scope. A project of another org or an inactive project is reported
// as not found, so that project existence is not leaked across orgs.
func (s *Service) tenantProject(ctx context.Context, orgID xdb.ID, reqProjectID string) (xdb.ID, error) {
	if reqProjectID == "" {
		tctx := authctx.FromContext(ctx)
		if tctx.IsAPIKey() {
			if keyProjectID := tctx.ProjectID(); !keyProjectID.IsZero() {
				reqProjectID = keyProjectID.String()
			}
		}
		if reqProjectID == "" {
			return xdb.ID(0), nil
		}
	}
	projectID, err := xdb.ParseID(reqProjectID)
	if err != nil {
		return xdb.ID(0), httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid project ID")
	}
	_, err = s.authorizer.Project(ctx, orgID, projectID)
	if err != nil {
		if errors.Is(err, authctx.ErrAccessDenied) {
			return xdb.ID(0), httperror.NewGrpcFromCtx(ctx, codes.NotFound, "project not found")
		}
		return xdb.ID(0), httperror.WrapWithCtx(ctx, err, "unable to find project")
	}
	return projectID, nil
}

// requestProject returns the project a mutation names explicitly, verified
// as tenantProject does, or a zero ID when the request names none: unlike
// tenantProject it does not default to the project of a restricted API key,
// since the row's own project is authorized by rowAccess, where the key
// reads an org-wide row but may not change it
func (s *Service) requestProject(ctx context.Context, orgID xdb.ID, reqProjectID string) (xdb.ID, error) {
	if reqProjectID == "" {
		return xdb.ID(0), nil
	}
	return s.tenantProject(ctx, orgID, reqProjectID)
}

// preconditionFailed returns the error of a request that the current state
// of the org refuses, and that the caller can make pass by changing that
// state: HTTP 409 Conflict with code "conflict", and gRPC FailedPrecondition.
// The pinned porto maps FailedPrecondition to HTTP 500, so it is built from
// the HTTP status and returned unwrapped.
func preconditionFailed(ctx context.Context, msgFormat string, vals ...any) *httperror.Error {
	e := httperror.NewFromCtx(ctx, http.StatusConflict, httperror.CodeConflict, msgFormat, vals...)
	e.RPCStatus = codes.FailedPrecondition
	return e
}

// defaultListLimit is used when a list request does not specify a limit
const defaultListLimit = 100

// Unique constraints of the CA tables, as PostgreSQL names them in a
// violation
const (
	uniqueIssuerLabelConstraint = "unique_issuer_org_project_label"
	uniqueIssuerSkidConstraint  = "unique_issuer_skid"
)

// requireCA returns Unavailable when the service has no issuer registry
func (s *Service) requireCA(ctx context.Context) error {
	if s.registry == nil {
		return httperror.NewGrpcFromCtx(ctx, codes.Unavailable, "CA is not configured")
	}
	return nil
}

// parseID parses a required ID of a request
func parseID(ctx context.Context, val, what string) (xdb.ID, error) {
	if val == "" {
		return xdb.ID(0), httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "missing %s", what)
	}
	id, err := xdb.ParseID(val)
	if err != nil {
		return xdb.ID(0), httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid %s", what)
	}
	return id, nil
}

// listCursor parses the cursor of a list request
func listCursor(ctx context.Context, cursor string) (query.Cursor, error) {
	c, err := query.ParseCursor(cursor)
	if err != nil {
		return query.Cursor{}, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid cursor")
	}
	return c, nil
}

// listLimit returns the page size of a list request
func listLimit(limit uint32) uint32 {
	return cmp.Or(limit, defaultListLimit)
}

// violates returns true when the error is a violation of the unique
// constraint
func violates(err error, constraint string) bool {
	return err != nil && strings.Contains(err.Error(), constraint)
}

// rowAccess checks that the caller may call the method on a row of the
// project of the org, after the interceptor authorized the scope of the
// request: a row named by its ID can belong to a project the request did
// not name. A trusted service caller passes. An API key passes when it is
// org-wide, or restricted to that project; a key restricted to a project
// reads an org-wide row (zero project) as the derived org Viewer and may not
// change it, so it passes only a method that allows Viewer. A user needs one
// of the roles the method allows at the project, where an org-wide role is
// inherited, and at the org for an org-wide row, which a member with project
// grants only holds as Viewer (DESIGN.md section 3.3). A project the caller
// cannot read, an inactive project and a project of another org are
// reported as not found, so that project existence does not leak; a project
// the caller reads but cannot act on at the method's roles is forbidden.
func (s *Service) rowAccess(ctx context.Context, orgID, projectID xdb.ID, method, what string) error {
	tctx := authctx.FromContext(ctx)
	if strings.HasPrefix(tctx.AppRole(), authctx.ServiceRolePrefix) {
		return nil
	}
	var allowed []string
	if rule := pb.GetMethodInfo(method); rule != nil {
		allowed = rule.AllowedRoles
	}
	if tctx.IsAPIKey() {
		keyProjectID := tctx.ProjectID()
		switch {
		case !projectID.IsZero():
			if !keyProjectID.IsZero() && keyProjectID.UInt64() != projectID.UInt64() {
				return httperror.NewGrpcFromCtx(ctx, codes.NotFound, "%s not found", what)
			}
			_, err := s.authorizer.Project(ctx, orgID, projectID)
			if err != nil {
				if errors.Is(err, authctx.ErrAccessDenied) {
					return httperror.NewGrpcFromCtx(ctx, codes.NotFound, "%s not found", what)
				}
				return httperror.WrapWithCtx(ctx, err, "unable to find project")
			}
		case !keyProjectID.IsZero() && !authctx.AllowsRole(allowed, pb.Role_Viewer):
			return httperror.NewGrpcFromCtx(ctx, codes.PermissionDenied, "access denied")
		}
		return nil
	}
	_, grants, err := s.authorizer.CheckRole(ctx, orgID, projectID, tctx.UserID(), pb.Role_Viewer.String())
	if err != nil {
		if errors.Is(err, authctx.ErrAccessDenied) || errors.Is(err, authctx.ErrInsufficientRole) || errors.Is(err, authctx.ErrOrgNotSelected) {
			return httperror.NewGrpcFromCtx(ctx, codes.NotFound, "%s not found", what)
		}
		return httperror.WrapWithCtx(ctx, err, "unable to resolve access")
	}
	if grants.HighestRole(projectID.UInt64(), allowed) == pb.Role_None {
		return httperror.NewGrpcFromCtx(ctx, codes.PermissionDenied, "access denied")
	}
	return nil
}

// listProjects returns the projects whose rows a list of the org without a
// project includes, next to the org-wide rows: nil, every project, for a
// trusted service caller, an API key and a member with an org-wide role;
// otherwise the projects the member has a grant in, since a member with
// project grants only sees nothing of the other projects (DESIGN.md
// section 3.3). An API key restricted to a project never lists without a
// project: tenantProject selects its project.
func (s *Service) listProjects(ctx context.Context, orgID xdb.ID) ([]uint64, error) {
	tctx := authctx.FromContext(ctx)
	if tctx.IsAPIKey() || strings.HasPrefix(tctx.AppRole(), authctx.ServiceRolePrefix) {
		return nil, nil
	}
	grants, err := s.authorizer.Grants(ctx, orgID, tctx.UserID())
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "unable to resolve access")
	}
	if grants.CanListAllProjects() {
		return nil, nil
	}
	return grants.GrantedProjectIDs(), nil
}

// orgIssuer returns the issuer with the ID when it belongs to the org and
// the caller may call the method on it (rowAccess); an issuer of another
// org, of the platform or of a project the caller cannot read is reported
// as not found
func (s *Service) orgIssuer(ctx context.Context, orgID xdb.ID, idVal, method string) (*model.Issuer, error) {
	id, err := parseID(ctx, idVal, "issuer ID")
	if err != nil {
		return nil, err
	}
	row, err := s.db.GetIssuer(ctx, id.UInt64())
	if err != nil {
		if xdb.IsNotFoundError(err) {
			return nil, httperror.NewGrpcFromCtx(ctx, codes.NotFound, "issuer not found")
		}
		return nil, httperror.WrapWithCtx(ctx, err, "unable to find issuer")
	}
	return s.visibleIssuer(ctx, orgID, row, method)
}

// visibleIssuer returns the issuer row when it belongs to the org and the
// caller may call the method on it (rowAccess)
func (s *Service) visibleIssuer(ctx context.Context, orgID xdb.ID, row *model.Issuer, method string) (*model.Issuer, error) {
	if row.OrgID.UInt64() != orgID.UInt64() {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.NotFound, "issuer not found")
	}
	err := s.rowAccess(ctx, orgID, row.ProjectID, method, "issuer")
	if err != nil {
		return nil, err
	}
	return row, nil
}

// issuerByLabel returns the issuer with the label of the project, or of the
// org when the project has none, from the DB
func (s *Service) issuerByLabel(ctx context.Context, orgID, projectID xdb.ID, label string) (*model.Issuer, error) {
	row, err := s.db.FindIssuer(ctx, orgID.UInt64(), projectID.UInt64(), label)
	if err != nil && xdb.IsNotFoundError(err) && !projectID.IsZero() {
		row, err = s.db.FindIssuer(ctx, orgID.UInt64(), 0, label)
	}
	if err != nil {
		if xdb.IsNotFoundError(err) {
			return nil, httperror.NewGrpcFromCtx(ctx, codes.NotFound, "issuer not found: %s", label)
		}
		return nil, httperror.WrapWithCtx(ctx, err, "unable to find issuer")
	}
	return row, nil
}

// orgProfile returns the profile with the ID when it belongs to the org and
// the caller may call the method on it (rowAccess); a profile of another
// org, of the platform or of a project the caller cannot read is reported
// as not found
func (s *Service) orgProfile(ctx context.Context, orgID xdb.ID, idVal, method string) (*model.CertificateProfile, error) {
	id, err := parseID(ctx, idVal, "profile ID")
	if err != nil {
		return nil, err
	}
	row, err := s.db.GetProfile(ctx, id.UInt64())
	if err != nil {
		if xdb.IsNotFoundError(err) {
			return nil, httperror.NewGrpcFromCtx(ctx, codes.NotFound, "profile not found")
		}
		return nil, httperror.WrapWithCtx(ctx, err, "unable to find profile")
	}
	if row.OrgID.UInt64() != orgID.UInt64() {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.NotFound, "profile not found")
	}
	err = s.rowAccess(ctx, orgID, row.ProjectID, method, "profile")
	if err != nil {
		return nil, err
	}
	return row, nil
}

// profileByLabel returns the profile with the label of the project, or of
// the org when the project has none, from the DB
func (s *Service) profileByLabel(ctx context.Context, orgID, projectID xdb.ID, label string) (*model.CertificateProfile, error) {
	row, err := s.db.FindProfile(ctx, orgID.UInt64(), projectID.UInt64(), label)
	if err != nil && xdb.IsNotFoundError(err) && !projectID.IsZero() {
		row, err = s.db.FindProfile(ctx, orgID.UInt64(), 0, label)
	}
	if err != nil {
		if xdb.IsNotFoundError(err) {
			return nil, httperror.NewGrpcFromCtx(ctx, codes.NotFound, "profile not found: %s", label)
		}
		return nil, httperror.WrapWithCtx(ctx, err, "unable to find profile")
	}
	return row, nil
}

// issuerPb converts an issuer row to its API message
func issuerPb(ctx context.Context, row *model.Issuer) (*pb.Issuer, error) {
	res, err := row.Pb()
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "invalid issuer config")
	}
	return res, nil
}
