package orgs

import (
	"context"
	"fmt"
	"strings"

	"github.com/effective-security/porto/xhttp/httperror"
	pb "github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/authctx"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xlog"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/emptypb"
)

// orgAccess builds the resolved org access from the user's grants,
// with the org alias and name taken from the membership rows
func orgAccess(rows model.MembershipInfoSlice, orgID, userID xdb.ID) *pb.OrgAccess {
	grants := authctx.GrantsFromMemberships(rows, orgID, userID)
	access := grants.OrgAccess()
	for _, m := range rows {
		if m.OrgID.UInt64() == orgID.UInt64() {
			access.OrgAlias = m.OrgAlias
			access.OrgName = m.OrgName
			break
		}
	}
	return access
}

// GetUserOrgs returns the orgs the caller can select, each once, with the
// resolved org role. A user with project grants only sees the org as a
// derived Viewer.
func (s *Service) GetUserOrgs(ctx context.Context, _ *emptypb.Empty) (*pb.UserOrgsResponse, error) {
	userID := authctx.FromContext(ctx).UserID()
	if userID.UInt64() == 0 {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.Unauthenticated, "user is required")
	}

	memberships, err := s.db.GetUserMemberships(ctx, userID.UInt64())
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "failed to get memberships")
	}
	res := &pb.UserOrgsResponse{}
	for _, orgID := range memberships.OrgIDs() {
		res.Orgs = append(res.Orgs, orgAccess(memberships, orgID, userID))
	}
	return res, nil
}

// GetUserMemberships returns the caller's resolved access to the org
// selected in the token and the caller's explicit grants in that org
func (s *Service) GetUserMemberships(ctx context.Context, _ *emptypb.Empty) (*pb.UserMemberships, error) {
	orgID, err := tokenOrg(ctx)
	if err != nil {
		return nil, err
	}
	userID := authctx.FromContext(ctx).UserID()

	memberships, err := s.db.ListMemberships(ctx, &query.ListMembershipsRequest{
		OrgID:     orgID.UInt64(),
		UserID:    userID.UInt64(),
		OrgStatus: pb.ItemStatus_Active,
	})
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "failed to get memberships")
	}
	return &pb.UserMemberships{
		Org:         orgAccess(memberships, orgID, userID),
		Memberships: memberships.Pb(),
	}, nil
}

// GetMembers returns grants and invites of the org selected in the token.
// With ProjectID only the project's grants are returned;
// with Scope Org only the org-wide grants are returned.
func (s *Service) GetMembers(ctx context.Context, req *pb.GetMembersRequest) (*pb.MembersResponse, error) {
	orgID, err := tokenOrg(ctx)
	if err != nil {
		return nil, err
	}
	projectID, err := parseOptionalID(ctx, req.ProjectID, "project ID")
	if err != nil {
		return nil, err
	}
	memberships, err := s.db.ListMemberships(ctx, &query.ListMembershipsRequest{
		OrgID:     orgID.UInt64(),
		ProjectID: projectID.UInt64(),
		Scope:     req.Scope,
	})
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "request failed")
	}
	invites, err := s.db.GetOrgInvites(ctx, orgID.UInt64())
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "request failed")
	}
	if projectID.UInt64() != 0 {
		invites = invites.FilterByProject(projectID.UInt64())
	} else if req.Scope == pb.Scope_Org {
		invites = invites.FilterByProject(0)
	}

	return &pb.MembersResponse{
		Memberships: memberships.Pb(),
		Invites:     invites.Pb(),
	}, nil
}

// checkGrantable verifies that the caller may grant (or revoke) the role at
// the scope and returns the caller's grants
func (s *Service) checkGrantable(ctx context.Context, orgID, projectID xdb.ID, role pb.Role_Enum) (*authctx.Grants, error) {
	callerID := authctx.FromContext(ctx).UserID()
	grants, err := s.authorizer.Grants(ctx, orgID, callerID)
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "failed to resolve access")
	}
	if projectID.UInt64() == 0 {
		if !grants.CanGrantOrgRole(role) {
			return nil, httperror.NewGrpcFromCtx(ctx, codes.PermissionDenied, "not allowed to grant role %s org-wide", role.String())
		}
	} else if !grants.CanGrantProjectRole(projectID.UInt64(), role) {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.PermissionDenied, "not allowed to grant role %s in the project", role.String())
	}
	return grants, nil
}

// AddMember grants a role org-wide (empty ProjectID) or in a project.
// If the user does not exist yet, an invite is created at the same scope.
func (s *Service) AddMember(ctx context.Context, req *pb.AddMemberRequest) (*pb.AddMemberResponse, error) {
	orgID, err := tokenOrg(ctx)
	if err != nil {
		return nil, err
	}
	projectID, err := parseOptionalID(ctx, req.ProjectID, "project ID")
	if err != nil {
		return nil, err
	}
	emailAddr := strings.ToLower(strings.TrimSpace(req.Email))
	if emailAddr == "" {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "email is required")
	}
	if req.Role == pb.Role_None {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "role is required")
	}

	trustycaCtx := authctx.FromContext(ctx)
	callerID := trustycaCtx.UserID()

	_, err = s.checkGrantable(ctx, orgID, projectID, req.Role)
	if err != nil {
		return nil, err
	}
	org, err := s.getActiveOrg(ctx, orgID)
	if err != nil {
		return nil, err
	}
	project, err := s.getProject(ctx, orgID, projectID)
	if err != nil {
		return nil, err
	}

	var res pb.AddMemberResponse

	user, err := s.db.GetUserByEmail(ctx, emailAddr)
	if err == nil {
		list, err := s.db.ListMemberships(ctx, &query.ListMembershipsRequest{
			OrgID:  orgID.UInt64(),
			UserID: user.ID.UInt64(),
		})
		if err != nil {
			return nil, httperror.WrapWithCtx(ctx, err, "request failed")
		}

		if member := list.FindMemberByUserID(user.ID.UInt64(), projectID.UInt64()); member != nil {
			if member.Role == req.Role {
				res.Membership = member.Pb()
				return &res, nil
			}
			return nil, httperror.NewGrpcFromCtx(ctx, codes.AlreadyExists, "user already member")
		}

		member, err := s.db.AddMember(ctx, &model.Membership{
			OrgID:     orgID,
			ProjectID: projectID,
			UserID:    user.ID,
			Role:      req.Role,
		})
		if err != nil {
			return nil, httperror.WrapWithCtx(ctx, err, "request failed")
		}
		res.Membership = member.Pb(org, project, user)

		s.authorizer.InvalidateUser(ctx, user.ID.String())
		logger.ContextKV(ctx, xlog.NOTICE,
			"org", orgID.UnderscoreString(),
			"project", projectID.UnderscoreString(),
			"invitee", emailAddr,
			"existing_user", user.ID.UInt64(),
			"role", member.Role.String())
		s.event(ctx, orgID, projectID, user.ID, memberEvent(projectID, pb.EventType_OrgMemberAdded, pb.EventType_ProjectMemberAdded),
			fmt.Sprintf("%s was added as %s", user.Email, member.Role.String()))
	} else {
		if !xdb.IsNotFoundError(err) {
			logger.ContextKV(ctx, xlog.WARNING,
				"email", emailAddr,
				"reason", "GetUserByEmail",
				"err", err.Error())
		}

		invite, err := s.db.CreateInvite(ctx, &model.Invite{
			OrgID:     orgID,
			ProjectID: projectID,
			InviterID: callerID,
			Email:     emailAddr,
			Role:      req.Role,
		})
		if err != nil {
			return nil, httperror.WrapWithCtx(ctx, err, "request failed")
		}
		res.Invite = invite.Pb()
		logger.ContextKV(ctx, xlog.NOTICE,
			"org", orgID.UnderscoreString(),
			"project", projectID.UnderscoreString(),
			"invitee", emailAddr,
			"role", invite.Role.DisplayName())
		s.event(ctx, orgID, projectID, invite.ID, memberEvent(projectID, pb.EventType_OrgMemberInvited, pb.EventType_ProjectMemberInvited),
			fmt.Sprintf("%s was invited as %s", emailAddr, invite.Role.String()))
		// TODO: emailer
	}

	return &res, nil
}

// memberEvent selects the org or project event type for the scope
func memberEvent(projectID xdb.ID, org, project pb.EventType_Enum) pb.EventType_Enum {
	if projectID.UInt64() != 0 {
		return project
	}
	return org
}

// findMember finds the grant at the scope by user ID or email
func (s *Service) findMember(ctx context.Context, orgID, projectID xdb.ID, userIDStr, email string) (*model.MembershipInfo, error) {
	memberships, err := s.db.ListMemberships(ctx, &query.ListMembershipsRequest{
		OrgID:     orgID.UInt64(),
		ProjectID: projectID.UInt64(),
		Scope:     model.ScopeOf(projectID),
	})
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "request failed")
	}

	var member *model.MembershipInfo
	if userIDStr != "" {
		userID, err := xdb.ParseID(userIDStr)
		if err != nil {
			return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid user ID")
		}
		member = memberships.FindMemberByUserID(userID.UInt64(), projectID.UInt64())
	} else if email != "" {
		member = memberships.FindMemberByEmail(strings.ToLower(strings.TrimSpace(email)), projectID.UInt64())
	} else {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "user ID or email is required")
	}
	if member == nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.NotFound, "unable to find member")
	}
	return member, nil
}

// checkLastOwner refuses to remove or demote the last org Owner
func (s *Service) checkLastOwner(ctx context.Context, orgID xdb.ID, member *model.MembershipInfo) error {
	if member.ProjectID.UInt64() != 0 || member.Role != pb.Role_Owner {
		return nil
	}
	owners, err := s.db.ListMemberships(ctx, &query.ListMembershipsRequest{
		OrgID: orgID.UInt64(),
		Scope: pb.Scope_Org,
		Role:  pb.Role_Owner,
	})
	if err != nil {
		return httperror.WrapWithCtx(ctx, err, "request failed")
	}
	if owners.CountOrgRole(orgID.UInt64(), pb.Role_Owner) <= 1 {
		return httperror.NewGrpcFromCtx(ctx, codes.FailedPrecondition, "the org must keep at least one owner")
	}
	return nil
}

// ChangeMemberRole changes the role of an existing grant at the requested
// scope. The caller must be allowed to grant both the current and the new
// role at that scope.
func (s *Service) ChangeMemberRole(ctx context.Context, req *pb.ChangeMemberRoleRequest) (*pb.Membership, error) {
	orgID, err := tokenOrg(ctx)
	if err != nil {
		return nil, err
	}
	projectID, err := parseOptionalID(ctx, req.ProjectID, "project ID")
	if err != nil {
		return nil, err
	}
	if req.Role == pb.Role_None {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "role is required")
	}
	_, err = s.checkGrantable(ctx, orgID, projectID, req.Role)
	if err != nil {
		return nil, err
	}

	member, err := s.findMember(ctx, orgID, projectID, req.UserID, req.Email)
	if err != nil {
		return nil, err
	}
	if member.Role == req.Role {
		return member.Pb(), nil
	}
	_, err = s.checkGrantable(ctx, orgID, projectID, member.Role)
	if err != nil {
		return nil, err
	}
	err = s.checkLastOwner(ctx, orgID, member)
	if err != nil {
		return nil, err
	}

	org, err := s.getActiveOrg(ctx, orgID)
	if err != nil {
		return nil, err
	}
	project, err := s.getProject(ctx, orgID, projectID)
	if err != nil {
		return nil, err
	}
	user, err := s.db.GetUser(ctx, member.UserID.UInt64())
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "unable to find user")
	}

	m, err := s.db.UpdateMemberRole(ctx, &query.UpdateMemberRoleRequest{
		OrgID:     orgID.UInt64(),
		ProjectID: projectID.UInt64(),
		UserID:    member.UserID.UInt64(),
		Role:      req.Role,
	})
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "request failed")
	}

	s.authorizer.InvalidateUser(ctx, user.ID.String())
	s.event(ctx, orgID, projectID, user.ID, memberEvent(projectID, pb.EventType_OrgMemberRoleChanged, pb.EventType_ProjectMemberRoleChanged),
		fmt.Sprintf("%s role changed from %s to %s", user.Email, member.Role.String(), req.Role.String()))

	return m.Pb(org, project, user), nil
}

// DeleteMember removes the grant at the requested scope:
// the project grant with ProjectID, otherwise the org-wide grant.
// The caller must be allowed to grant the member's role at that scope.
func (s *Service) DeleteMember(ctx context.Context, req *pb.DeleteMemberRequest) (*emptypb.Empty, error) {
	orgID, err := tokenOrg(ctx)
	if err != nil {
		return nil, err
	}
	if req.UserID == "" {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid user ID")
	}
	projectID, err := parseOptionalID(ctx, req.ProjectID, "project ID")
	if err != nil {
		return nil, err
	}

	member, err := s.findMember(ctx, orgID, projectID, req.UserID, "")
	if err != nil {
		return nil, err
	}
	_, err = s.checkGrantable(ctx, orgID, projectID, member.Role)
	if err != nil {
		return nil, err
	}
	err = s.checkLastOwner(ctx, orgID, member)
	if err != nil {
		return nil, err
	}

	_, err = s.db.DeleteMember(ctx, &query.DeleteMemberRequest{
		OrgID:     orgID.UInt64(),
		ProjectID: projectID.UInt64(),
		UserID:    member.UserID.UInt64(),
		Scope:     model.ScopeOf(projectID),
	})
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "request failed")
	}

	s.authorizer.InvalidateUser(ctx, member.UserID.String())
	s.event(ctx, orgID, projectID, member.UserID, memberEvent(projectID, pb.EventType_OrgMemberRemoved, pb.EventType_ProjectMemberRemoved),
		fmt.Sprintf("%s (%s) was removed", member.Email, member.Role.String()))

	return &emptypb.Empty{}, nil
}

// DeleteInvite deletes the invite at the requested scope
func (s *Service) DeleteInvite(ctx context.Context, req *pb.DeleteInviteRequest) (*emptypb.Empty, error) {
	orgID, err := tokenOrg(ctx)
	if err != nil {
		return nil, err
	}
	projectID, err := parseOptionalID(ctx, req.ProjectID, "project ID")
	if err != nil {
		return nil, err
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "email is required")
	}

	_, err = s.db.DeleteInvite(ctx, &query.DeleteInviteRequest{
		OrgID:     orgID.UInt64(),
		ProjectID: projectID.UInt64(),
		Email:     email,
		Scope:     model.ScopeOf(projectID),
	})
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "request failed")
	}

	return &emptypb.Empty{}, nil
}
