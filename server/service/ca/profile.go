package ca

import (
	"context"
	"strings"

	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/trustyca/api/pb"
	core "github.com/effective-security/trustyca/internal/ca"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/internal/events"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xlog"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/emptypb"
)

// RegisterProfile creates a profile of the org or of the project, or
// replaces the one with the same label in the same scope. The profile is
// validated as the authority will sign with it; its issuer label binds it
// to an issuer of the org, or to any issuer that allows it.
func (s *Service) RegisterProfile(ctx context.Context, req *pb.RegisterProfileRequest) (*pb.CertProfile, error) {
	if req == nil || req.Profile == nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "missing profile")
	}
	err := s.requireCA(ctx)
	if err != nil {
		return nil, err
	}
	def := req.Profile
	def.Label = strings.TrimSpace(def.Label)
	def.IssuerLabel = strings.TrimSpace(def.IssuerLabel)
	if def.Label == "" {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "missing profile label")
	}
	if len(def.Label) > model.MaxLenForLabel {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid profile label length")
	}
	if def.IssuerLabel == "" {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "missing issuer label")
	}
	if len(def.IssuerLabel) > model.MaxLenForLabel {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid issuer label length")
	}
	if _, err := core.ProfileFromPb(def); err != nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "%s", err.Error())
	}
	orgID, err := s.tenantOrg(ctx, req.OrgID)
	if err != nil {
		return nil, err
	}
	projectID, err := s.tenantProject(ctx, orgID, req.ProjectID)
	if err != nil {
		return nil, err
	}

	m, err := model.NewCertificateProfile(orgID, projectID, def)
	if err != nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "%s", err.Error())
	}
	res, err := s.db.RegisterProfile(ctx, m)
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "failed to register profile")
	}
	s.registry.InvalidateProfile(orgID, projectID, res.Label)
	logger.ContextKV(ctx, xlog.NOTICE,
		"status", "profile_registered",
		"profile_id", res.ID.UnderscoreString(),
		"org_id", res.OrgID.UnderscoreString(),
		"project_id", res.ProjectID.UnderscoreString(),
		"profile", res.Label,
		"issuer", res.IssuerLabel)
	events.New(ctx, ServiceName, pb.EventType_ProfileRegistered, "Profile registered").
		Org(orgID).
		Project(projectID).
		Reference(res.ID).
		Description("profile %q registered for issuer %q", res.Label, res.IssuerLabel).
		Emit(s.orgs)
	return profilePb(ctx, res)
}

// GetProfile returns a profile of the org by ID, or by label resolved in
// the project then in the org
func (s *Service) GetProfile(ctx context.Context, req *pb.GetProfileRequest) (*pb.CertProfile, error) {
	if req == nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "missing request")
	}
	orgID, err := s.tenantOrg(ctx, req.OrgID)
	if err != nil {
		return nil, err
	}
	var row *model.CertificateProfile
	switch {
	case req.ID != "":
		row, err = s.orgProfile(ctx, orgID, req.ID, pb.CA_GetProfile_FullMethodName)
	case req.Label != "":
		var projectID xdb.ID
		projectID, err = s.tenantProject(ctx, orgID, req.ProjectID)
		if err != nil {
			return nil, err
		}
		row, err = s.profileByLabel(ctx, orgID, projectID, req.Label)
	default:
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "profile ID or label is required")
	}
	if err != nil {
		return nil, err
	}
	return profilePb(ctx, row)
}

// ListProfiles returns the profiles of the org, newest first; a project
// limits the result to its own profiles. Without a project, a member with
// project grants only lists the org-wide profiles and those of its
// projects.
func (s *Service) ListProfiles(ctx context.Context, req *pb.ListProfilesRequest) (*pb.ProfilesResponse, error) {
	if req == nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "missing request")
	}
	orgID, err := s.tenantOrg(ctx, req.OrgID)
	if err != nil {
		return nil, err
	}
	projectID, err := s.tenantProject(ctx, orgID, req.ProjectID)
	if err != nil {
		return nil, err
	}
	cursor, err := listCursor(ctx, req.Cursor)
	if err != nil {
		return nil, err
	}
	q := &query.ListProfilesRequest{
		OrgID:       orgID.UInt64(),
		ProjectID:   projectID.UInt64(),
		IssuerLabel: req.IssuerLabel,
		Limit:       listLimit(req.Limit),
		Offset:      req.Offset,
		Cursor:      cursor,
	}
	if projectID.IsZero() {
		q.ProjectIDs, err = s.listProjects(ctx, orgID)
		if err != nil {
			return nil, err
		}
	}
	res, err := s.db.ListProfiles(ctx, q)
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "failed to list profiles")
	}
	list, err := res.Pb()
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "invalid profile config")
	}
	return list, nil
}

// DeleteProfile deletes a profile of the org
func (s *Service) DeleteProfile(ctx context.Context, req *pb.DeleteProfileRequest) (*emptypb.Empty, error) {
	if req == nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "missing request")
	}
	err := s.requireCA(ctx)
	if err != nil {
		return nil, err
	}
	orgID, err := s.tenantOrg(ctx, req.OrgID)
	if err != nil {
		return nil, err
	}
	row, err := s.orgProfile(ctx, orgID, req.ID, pb.CA_DeleteProfile_FullMethodName)
	if err != nil {
		return nil, err
	}
	deleted, err := s.db.DeleteProfile(ctx, orgID.UInt64(), row.ID.UInt64())
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "failed to delete profile")
	}
	if deleted == 0 {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.NotFound, "profile not found")
	}
	s.registry.InvalidateProfile(row.OrgID, row.ProjectID, row.Label)
	logger.ContextKV(ctx, xlog.NOTICE,
		"status", "profile_deleted",
		"profile_id", row.ID.UnderscoreString(),
		"org_id", row.OrgID.UnderscoreString(),
		"project_id", row.ProjectID.UnderscoreString(),
		"profile", row.Label)
	events.New(ctx, ServiceName, pb.EventType_ProfileDeleted, "Profile deleted").
		Org(orgID).
		Project(row.ProjectID).
		Reference(row.ID).
		Description("profile %q deleted", row.Label).
		Emit(s.orgs)
	return &emptypb.Empty{}, nil
}

// profilePb converts a profile row to its API message
func profilePb(ctx context.Context, row *model.CertificateProfile) (*pb.CertProfile, error) {
	res, err := row.Pb()
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "invalid profile config")
	}
	return res, nil
}
