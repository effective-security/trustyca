package orgs

import (
	"context"
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

// GetUserMemberships returns list of calling user memberships
func (s *Service) GetUserMemberships(ctx context.Context, req *emptypb.Empty) (*pb.UserMemberships, error) {
	idn := authctx.FromContext(ctx)
	userID := idn.UserID()

	memberships, err := s.db.ListMemberships(ctx, &query.ListMembershipsRequest{
		UserID:    userID.UInt64(),
		OrgStatus: pb.ItemStatus_Active,
	})
	if err != nil {
		return nil, err
	}
	res := &pb.UserMemberships{
		Memberships: memberships.Pb(),
	}
	return res, nil
}

// GetMembers returns list of membership info for the org by org ID
func (s *Service) GetMembers(ctx context.Context, req *pb.GetMembersRequest) (*pb.MembersResponse, error) {
	id, err := xdb.ParseID(req.OrgID)
	if err != nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid org ID")
	}

	memberships, err := s.db.ListMemberships(ctx, &query.ListMembershipsRequest{
		OrgID: id.UInt64(),
		//OrgStatus: pb.ItemStatus_Active,
	})
	if err != nil {
		return nil, err
	}
	invites, err := s.db.GetOrgInvites(ctx, id.UInt64())
	if err != nil {
		return nil, err
	}
	res := &pb.MembersResponse{
		Memberships: memberships.Pb(),
		Invites:     invites.Pb(),
	}

	return res, nil
}

// AddMember adds a user to Org
func (s *Service) AddMember(ctx context.Context, req *pb.AddMemberRequest) (*pb.AddMemberResponse, error) {
	orgID, err := xdb.ParseID(req.OrgID)
	if err != nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid org ID")
	}
	emailAddr := strings.ToLower(strings.TrimSpace(req.Email))
	if emailAddr == "" {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "email is required")
	}

	trustycaCtx := authctx.FromContext(ctx)
	callerID := trustycaCtx.UserID()

	callerRole := authctx.FindCallerRole(trustycaCtx, orgID.String())
	// only owner can add owner
	if req.Role == pb.Role_Owner && callerRole != pb.Role_Owner {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.PermissionDenied, "owner role required")
	}

	org, err := s.db.GetOrg(ctx, orgID.UInt64())
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "unable to find org")
	}
	if org.Status == pb.ItemStatus_Inactive {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.FailedPrecondition, "org is deleted")
	}

	var res pb.AddMemberResponse

	user, err := s.db.GetUserByEmail(ctx, emailAddr)
	if err == nil {
		list, err := s.db.ListMemberships(ctx, &query.ListMembershipsRequest{
			OrgID: orgID.UInt64(),
			//OrgStatus: pb.ItemStatus_Active,
		})
		if err != nil {
			return nil, httperror.WrapWithCtx(ctx, err, "request failed")
		}

		if member := list.FindMemberByUserID(user.ID.UInt64()); member != nil {
			if member.Role == req.Role {
				res.Membership = member.Pb()
				return &res, nil
			}
			return nil, httperror.NewGrpcFromCtx(ctx, codes.AlreadyExists, "user already member")
		}

		member, err := s.db.AddMember(ctx, &model.Membership{
			OrgID:  orgID,
			UserID: user.ID,
			Role:   req.Role,
		})
		if err != nil {
			return nil, httperror.WrapWithCtx(ctx, err, "request failed")
		}
		res.Membership = member.Pb(org, user)

		s.roleChecker.InvalidateCache(ctx, user.ID.String())
		logger.ContextKV(ctx, xlog.NOTICE,
			"org", orgID.UnderscoreString(),
			"invitee", emailAddr,
			"existing_user", user.ID.UInt64(),
			"role", member.Role.String())

		// TODO: events
		// s.db.TryCreateEvent(&model.Event{
		// 	OrgID:   orgID,
		// 	Type:        pb.EventType_MemberAdded,
		// 	Email:       xdb.NULLString(trustycaCtx.Email()),
		// 	Source:      xdb.NULLString(trustycaCtx.Target()),
		// 	Title:       fmt.Sprintf("(%s) was added as %s", user.Email, member.Role.DisplayName()),
		// 	Description: xdb.NULLString(fmt.Sprintf("Existing user %s (%s) was added as %s by %s", user.Name, user.Email, member.Role.DisplayName(), trustycaCtx.Email())),
		// })
	} else {
		if !xdb.IsNotFoundError(err) {
			logger.ContextKV(ctx, xlog.WARNING,
				"email", emailAddr,
				"reason", "GetUserByEmail",
				"err", err.Error())
		}

		invite, err := s.db.CreateInvite(ctx, &model.Invite{
			OrgID:     orgID,
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
			"invitee", emailAddr,
			"role", invite.Role.DisplayName())
		// TODO: emailer and events
		/*
			err = s.Emailer.SendHTMLTemplate(ctx,
				[]string{emailAddr},
				"Org invite",
				"/emails/org_invite.html",
				&templates.OrgInviteEmail{
					InviterName:  trustycaCtx.Name(),
					InviterEmail: trustycaCtx.Email(),
					AppURL:       s.cfg.AppURL,
					Org: org.Name,
				},
			)
			if err != nil {
				logger.ContextKV(ctx, xlog.ERROR,
					"email", emailAddr,
					"reason", "SendHTMLTemplate",
					"err", err.Error())
			}

			s.db.TryCreateEvent(&model.Event{
				OrgID:   orgID,
				Type:        pb.EventType_MemberAdded,
				Email:       xdb.NULLString(trustycaCtx.Email()),
				Source:      xdb.NULLString(trustycaCtx.Target()),
				Title:       fmt.Sprintf("%s was invited as %s", emailAddr, req.Role),
				Description: xdb.NULLString(fmt.Sprintf("User %s was invited as %s by %s", emailAddr, req.Role, trustycaCtx.Email())),
			})
		*/
	}

	return &res, nil
}

// ChangeMemberRole changes the role of a user in the org
func (s *Service) ChangeMemberRole(ctx context.Context, req *pb.ChangeMemberRoleRequest) (*pb.Membership, error) {
	orgID, err := xdb.ParseID(req.OrgID)
	if err != nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid org ID")
	}

	trustycaCtx := authctx.FromContext(ctx)
	callerRole := authctx.FindCallerRole(trustycaCtx, orgID.String())

	if req.Role == pb.Role_Owner && callerRole != pb.Role_Owner {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.PermissionDenied, "forbidden to change owner")
	}

	memberships, err := s.db.ListMemberships(ctx, &query.ListMembershipsRequest{
		OrgID: orgID.UInt64(),
		//OrgStatus: pb.ItemStatus_Active,
	})
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "request failed")
	}

	var member *model.MembershipInfo
	if req.UserID != "" {
		userID, err := xdb.ParseID(req.UserID)
		if err != nil {
			return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid user ID")
		}
		member = memberships.FindMemberByUserID(userID.UInt64())
	} else if req.Email != "" {
		member = memberships.FindMemberByEmail(req.Email)
	}
	if member == nil {
		return nil, httperror.WrapWithCtx(ctx, err, "unable to find user")
	}

	if member.Role == pb.Role_Owner && callerRole != pb.Role_Owner {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.PermissionDenied, "forbidden to change owner")
	}

	org, err := s.db.GetOrg(ctx, orgID.UInt64())
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "unable to find org")
	}
	if org.Status == pb.ItemStatus_Inactive {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.FailedPrecondition, "org is deleted")
	}
	user, err := s.db.GetUser(ctx, member.UserID.UInt64())
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "unable to find user")
	}

	m, err := s.db.UpdateMemberRole(ctx, orgID.UInt64(), member.UserID.UInt64(), req.Role)
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "request failed")
	}

	s.roleChecker.InvalidateCache(ctx, user.ID.String())

	// TODO: events
	// s.db.TryCreateEvent(&model.Event{
	// 	ProjectID:   projectID,
	// 	Type:        pb.EventType_MemberAdded,
	// 	Email:       xdb.NULLString(trustycaCtx.Email()),
	// 	Source:      xdb.NULLString(trustycaCtx.Target()),
	// 	Title:       fmt.Sprintf("%s (%s) was changed to %s", member.Email, member.Role.DisplayName(), req.Role.DisplayName()),
	// 	Description: xdb.NULLString(fmt.Sprintf("User %s (%s) was changed to %s by %s", member.Name, member.Email, req.Role.DisplayName(), trustycaCtx.Email())),
	// })

	return m.Pb(org, user), nil
}

// DeleteMember deletes a user from the project
func (s *Service) DeleteMember(ctx context.Context, req *pb.DeleteMemberRequest) (*emptypb.Empty, error) {
	orgID, err := xdb.ParseID(req.OrgID)
	if err != nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid org ID")
	}
	userID, err := xdb.ParseID(req.UserID)
	if err != nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid user ID")
	}

	memberships, err := s.db.ListMemberships(ctx, &query.ListMembershipsRequest{
		OrgID: orgID.UInt64(),
		//ProjectStatus: pb.ItemStatus_Active,
	})
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "request failed")
	}

	member := memberships.FindMemberByUserID(userID.UInt64())
	if member == nil {
		return nil, httperror.WrapWithCtx(ctx, err, "unable to find user")
	}
	if member.Role == pb.Role_Owner {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.PermissionDenied, "forbidden to delete owner")
	}

	_, err = s.db.DeleteMember(ctx, &query.DeleteMemberRequest{
		OrgID:  orgID.UInt64(),
		UserID: member.UserID.UInt64(),
	})
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "request failed")
	}

	s.roleChecker.InvalidateCache(ctx, member.UserID.String())

	// TODO: events
	// if rows == 1 {
	// }

	return &emptypb.Empty{}, nil
}

// DeleteInvite deletes an invite from the project
func (s *Service) DeleteInvite(ctx context.Context, req *pb.DeleteInviteRequest) (*emptypb.Empty, error) {
	orgID, err := xdb.ParseID(req.OrgID)
	if err != nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid org ID")
	}

	_, err = s.db.DeleteInvite(ctx, &query.DeleteInviteRequest{
		OrgID: orgID.UInt64(),
		Email: req.Email,
	})
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "request failed")
	}

	// TODO: events

	return &emptypb.Empty{}, nil
}
