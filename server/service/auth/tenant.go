package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/porto/xhttp/identity"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/authctx"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/x/values"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/jwt"
	"google.golang.org/grpc/codes"
)

// orgSelection is the org context written into a token
type orgSelection struct {
	OrgID  xdb.ID
	Role   pb.Role_Enum
	Source pb.RoleSource_Enum
	// Orgs maps every accessible org ID to the resolved role
	Orgs map[string]string
}

// setOrgClaims writes the selected org into the token claims.
// The token identifies the selected org and carries the resolved role for
// display only; permissions are resolved from the grants at request time.
func (o *orgSelection) setOrgClaims(claims jwt.MapClaims) {
	delete(claims, "orgs")
	if o == nil || o.OrgID.UInt64() == 0 {
		delete(claims, authctx.ClaimOrg)
		delete(claims, authctx.ClaimOrgRole)
		delete(claims, authctx.ClaimOrgRoleSource)
		return
	}
	claims[authctx.ClaimOrg] = o.OrgID.String()
	claims[authctx.ClaimOrgRole] = o.Role.String()
	claims[authctx.ClaimOrgRoleSource] = authctx.RoleSourceClaim(o.Source)
}

// resolveOrgs returns the resolved role of the user in every accessible org
func resolveOrgs(memberships model.MembershipInfoSlice, userID xdb.ID) map[string]string {
	res := map[string]string{}
	for _, orgID := range memberships.OrgIDs() {
		role, _ := authctx.GrantsFromMemberships(memberships, orgID, userID).ResolvedOrgRole()
		res[orgID.String()] = role.String()
	}
	return res
}

// selectOrg resolves the user's access to the org from the memberships.
// It returns nil when the user has no grant in the org.
func selectOrg(memberships model.MembershipInfoSlice, orgID, userID xdb.ID) *orgSelection {
	grants := authctx.GrantsFromMemberships(memberships, orgID, userID)
	if !grants.IsMember() {
		return nil
	}
	role, source := grants.ResolvedOrgRole()
	return &orgSelection{
		OrgID:  orgID,
		Role:   role,
		Source: source,
		Orgs:   resolveOrgs(memberships, userID),
	}
}

// initialOrg picks the org for a fresh login: the first accessible org, or a
// default org created for a user without any grant when configured.
// TODO: prefer the most recently used org.
func (s *Service) initialOrg(ctx context.Context, user *model.User) *orgSelection {
	memberships, err := s.db.GetUserMemberships(ctx, user.ID.UInt64())
	if err != nil {
		logger.ContextKV(ctx, xlog.ERROR, "reason", "GetUserMemberships", "err", err.Error())
		return nil
	}
	if len(memberships) == 0 && s.cfg.Orgs.DefaultOrgName != "" {
		org, err := s.db.RegisterOrg(ctx, &model.Org{
			Name:   s.cfg.Orgs.DefaultOrgName,
			Status: pb.ItemStatus_Active,
		}, user.ID.UInt64())
		if err != nil {
			logger.ContextKV(ctx, xlog.ERROR, "reason", "CreateDefaultOrg", "err", err.Error())
			return nil
		}
		logger.ContextKV(ctx, xlog.INFO,
			"status", "CreateDefaultOrg",
			"name", org.Name,
			"alias", org.Alias,
			"owner_id", user.ID.UInt64(),
		)
		if s.cfg.Orgs.DefaultProjectName != "" {
			_, err = s.db.RegisterProject(ctx, &model.Project{
				OrgID:  org.ID,
				Name:   s.cfg.Orgs.DefaultProjectName,
				Status: pb.ItemStatus_Active,
			})
			if err != nil {
				logger.ContextKV(ctx, xlog.ERROR, "reason", "CreateDefaultProject", "err", err.Error())
			}
		}
		memberships, err = s.db.GetUserMemberships(ctx, user.ID.UInt64())
		if err != nil {
			logger.ContextKV(ctx, xlog.ERROR, "reason", "GetUserMemberships", "err", err.Error())
			return nil
		}
	}
	orgIDs := memberships.OrgIDs()
	if len(orgIDs) == 0 {
		return nil
	}
	return selectOrg(memberships, orgIDs[0], user.ID)
}

// SelectOrg verifies the caller's access to the org and returns a new token
// scoped to it. Access requires an active org-wide or project grant.
func (s *Service) SelectOrg(ctx context.Context, req *pb.SelectOrgRequest) (*pb.UserTokenResponse, error) {
	orgID, err := xdb.ParseID(req.OrgID)
	if err != nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid org ID")
	}

	trustyCtx := authctx.FromContext(ctx)
	if trustyCtx.OrgRole() == pb.Role_APIKey {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.PermissionDenied, "API key not allowed")
	}

	userID := trustyCtx.UserID()
	if userID.UInt64() == 0 {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.Unauthenticated, "invalid user")
	}

	user, err := s.db.GetUser(ctx, userID.UInt64())
	if err != nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.PermissionDenied, "unable to find user").WithCause(err)
	}

	memberships, err := s.db.GetUserMemberships(ctx, userID.UInt64())
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "unable to get memberships")
	}

	sel := selectOrg(memberships, orgID, userID)
	if sel == nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.PermissionDenied, "no access to the requested organization")
	}

	caller := identity.FromContext(ctx).Identity()
	claims := caller.Claims()

	ui := &pb.UserInfo{
		ID:            userID.String(),
		Name:          user.Name,
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
		Role:          caller.Role(),
		Orgs:          sel.Orgs,
		OrgID:         orgID.String(),
		OrgRole:       sel.Role.String(),
		OrgRoleSource: authctx.RoleSourceClaim(sel.Source),
	}

	sel.setOrgClaims(claims)
	claims["email"] = user.Email
	claims["email_verified"] = user.EmailVerified
	claims["name"] = user.Name
	claims["sub"] = ui.ID
	claims["role"] = ui.Role

	// the new token keeps the original expiry
	tokenStr, err := s.JwtSigner.Sign(ctx, claims)
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "failed to sign JWT")
	}

	res := &pb.UserTokenResponse{
		Token: &pb.Token{
			TokenType: caller.TokenType(),
			// If the authentication method is JWT Cookie, do not return the access token
			AccessToken: values.Select(trustyCtx.AuthMethod() == identity.MethodJWTCookie, "", tokenStr),
			ExpiresAt:   claims.TimeVal("exp").Format(time.RFC3339),
			IssuedAt:    claims.TimeVal("iat").Format(time.RFC3339),
			Issuer:      claims.String("iss"),
			Audience:    claims.String("aud"),
			Provider:    pb.IDP_Undefined.Parse(claims.String("provider")),
		},
		UserInfo: ui,
	}
	if cnf := claims.CNF(); cnf != nil {
		res.Token.Jkt = cnf.Jkt
	}

	name := values.StringsCoalesce(ui.Name, ui.Email)
	s.db.TryCreateEvent(&model.Event{
		OrgID:       orgID,
		Type:        pb.EventType_UserLogin,
		Email:       xdb.NULLString(ui.Email),
		Source:      xdb.NULLString(trustyCtx.Target()),
		Title:       fmt.Sprintf("%s selected the org as %s", name, sel.Role.String()),
		ReferenceID: userID,
	})

	return res, nil
}
