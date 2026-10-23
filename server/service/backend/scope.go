package backend

import (
	"context"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/authctx"
	"github.com/effective-security/trustyca/internal/db"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/xdb"
	"google.golang.org/grpc/codes"
)

// tenantScope resolves the tenant scope of a CA request and authorizes the
// rows the request reaches: the org and the project of the request, and the
// project of a row found by ID. It reads the CA tables and the orgs only.
type tenantScope struct {
	authorizer authctx.Authorizer
	db         db.CaReadonlyDb
	orgs       db.OrgsReadonlyDb
}

// newTenantScope returns the scope checks over the authorizer and the tables
func newTenantScope(authorizer authctx.Authorizer, caDb db.CaReadonlyDb, orgsDb db.OrgsReadonlyDb) *tenantScope {
	return &tenantScope{
		authorizer: authorizer,
		db:         caDb,
		orgs:       orgsDb,
	}
}

// Org returns the org of a tenant request. A user or API key token
// carries the selected org, and an explicit OrgID in the request must match
// it. A trusted service caller (RA, CIS, jobs over mTLS) has no org in its
// token and names the org explicitly; the org must exist and be active.
func (s *tenantScope) Org(ctx context.Context, reqOrgID string) (xdb.ID, error) {
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

// Project returns the project of a tenant request, or a zero ID for
// the org scope. A project of another org or an inactive project is reported
// as not found, so that project existence is not leaked across orgs.
func (s *tenantScope) Project(ctx context.Context, orgID xdb.ID, reqProjectID string) (xdb.ID, error) {
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

// RequestProject returns the project a mutation names explicitly, verified
// as Project does, or a zero ID when the request names none: unlike
// Project it does not default to the project of a restricted API key,
// since the row's own project is authorized by RowAccess, where the key
// reads an org-wide row but may not change it
func (s *tenantScope) RequestProject(ctx context.Context, orgID xdb.ID, reqProjectID string) (xdb.ID, error) {
	if reqProjectID == "" {
		return xdb.ID(0), nil
	}
	return s.Project(ctx, orgID, reqProjectID)
}

// RowAccess checks that the caller may call the method on a row of the
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
func (s *tenantScope) RowAccess(ctx context.Context, orgID, projectID xdb.ID, method, what string) error {
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

// ListProjects returns the projects whose rows a list of the org without a
// project includes, next to the org-wide rows: nil, every project, for a
// trusted service caller, an API key and a member with an org-wide role;
// otherwise the projects the member has a grant in, since a member with
// project grants only sees nothing of the other projects (DESIGN.md
// section 3.3). An API key restricted to a project never lists without a
// project: Project selects its project.
func (s *tenantScope) ListProjects(ctx context.Context, orgID xdb.ID) ([]uint64, error) {
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

// Issuer returns the issuer with the ID when it belongs to the org and
// the caller may call the method on it (RowAccess); an issuer of another
// org, of the platform or of a project the caller cannot read is reported
// as not found
func (s *tenantScope) Issuer(ctx context.Context, orgID xdb.ID, idVal, method string) (*model.Issuer, error) {
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
	return s.VisibleIssuer(ctx, orgID, row, method)
}

// VisibleIssuer returns the issuer row when it belongs to the org and the
// caller may call the method on it (RowAccess)
func (s *tenantScope) VisibleIssuer(ctx context.Context, orgID xdb.ID, row *model.Issuer, method string) (*model.Issuer, error) {
	if row.OrgID.UInt64() != orgID.UInt64() {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.NotFound, "issuer not found")
	}
	err := s.RowAccess(ctx, orgID, row.ProjectID, method, "issuer")
	if err != nil {
		return nil, err
	}
	return row, nil
}

// IssuerByLabel returns the issuer with the label of the project, or of the
// org when the project has none, from the DB
func (s *tenantScope) IssuerByLabel(ctx context.Context, orgID, projectID xdb.ID, label string) (*model.Issuer, error) {
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

// Profile returns the profile with the ID when it belongs to the org and
// the caller may call the method on it (RowAccess); a profile of another
// org, of the platform or of a project the caller cannot read is reported
// as not found
func (s *tenantScope) Profile(ctx context.Context, orgID xdb.ID, idVal, method string) (*model.CertificateProfile, error) {
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
	err = s.RowAccess(ctx, orgID, row.ProjectID, method, "profile")
	if err != nil {
		return nil, err
	}
	return row, nil
}

// ProfileByLabel returns the profile with the label of the project, or of
// the org when the project has none, from the DB
func (s *tenantScope) ProfileByLabel(ctx context.Context, orgID, projectID xdb.ID, label string) (*model.CertificateProfile, error) {
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
