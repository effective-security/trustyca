package auth

import (
	"context"
	"net/http"
	"time"

	"github.com/effective-security/porto/restserver"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/porto/xhttp/identity"
	"github.com/effective-security/porto/xhttp/marshal"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/authctx"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/events"
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
		events.New(ctx, ServiceName, pb.EventType_OrgCreated, "Org created").
			Org(org.ID).
			Reference(org.ID).
			Email(user.Email).
			Description("default org %q created for %s", org.Name, user.Email).
			Emit(s.db)

		if s.cfg.Orgs.DefaultProjectName != "" {
			project, err := s.db.RegisterProject(ctx, &model.Project{
				OrgID:  org.ID,
				Name:   s.cfg.Orgs.DefaultProjectName,
				Status: pb.ItemStatus_Active,
			})
			if err != nil {
				logger.ContextKV(ctx, xlog.ERROR, "reason", "CreateDefaultProject", "err", err.Error())
			} else {
				events.New(ctx, ServiceName, pb.EventType_ProjectCreated, "Project created").
					Org(org.ID).
					Project(project.ID).
					Reference(project.ID).
					Email(user.Email).
					Description("default project %q created", project.Name).
					Emit(s.db)
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
// scoped to it, with the original expiry. Access requires an active
// org-wide or project grant.
//
// A cookie session does not receive AccessToken, and gRPC cannot set a
// cookie: such a session switches the org with POST pb.PathForAuthOrg
// (AuthOrgHandler), which writes the new token into the auth cookie.
func (s *Service) SelectOrg(ctx context.Context, req *pb.SelectOrgRequest) (*pb.UserTokenResponse, error) {
	res, err := s.selectOrgToken(ctx, req)
	if err != nil {
		return nil, err
	}
	// gRPC has no Authorization header of its own: the auth method of the
	// identity tells a cookie session
	omitCookieAccessToken(ctx, res, "")
	return res, nil
}

// selectOrgToken verifies the caller's access to the org and returns a new
// token scoped to it. AccessToken is always set; the callers omit it from
// the response of a cookie session.
func (s *Service) selectOrgToken(ctx context.Context, req *pb.SelectOrgRequest) (*pb.UserTokenResponse, error) {
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
			TokenType:   caller.TokenType(),
			AccessToken: tokenStr,
			ExpiresAt:   claims.TimeVal("exp").Format(time.RFC3339),
			IssuedAt:    claims.TimeVal("iat").Format(time.RFC3339),
			Issuer:      claims.String("iss"),
			Audience:    claims.String("aud"),
			Provider:    tokenProvider(claims),
		},
		UserInfo: ui,
	}
	if cnf := claims.CNF(); cnf != nil {
		res.Token.Jkt = cnf.Jkt
	}

	events.New(ctx, ServiceName, pb.EventType_UserSignedIn, "User signed in").
		Org(orgID).
		Reference(userID).
		Email(user.Email).
		Description("%s signed in as %s", user.Email, sel.Role.DisplayName()).
		Emit(s.db)

	return res, nil
}

// AuthOrgHandler handles pb.PathForAuthOrg: the org switch of a REST
// caller, the one a cookie session uses. A cookie session (the auth cookie
// and no Authorization header) receives the new token in the auth cookie,
// with a new CSRF cookie, and the response omits AccessToken; the cookies
// last until the token expires with RememberMe, else for the browser
// session. A caller with an Authorization header receives AccessToken, and
// its cookies are not replaced.
func (s *Service) AuthOrgHandler() restserver.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ restserver.Params) {
		var req pb.SelectOrgRequest
		if err := marshal.DecodeBody(w, r, &req); err != nil {
			return
		}

		ctx := r.Context()
		res, err := s.selectOrgToken(ctx, &req)
		if err != nil {
			marshal.WriteJSON(w, r, err)
			return
		}

		authorization := r.Header.Get(header.Authorization)
		if authorization == "" && authctx.FromContext(ctx).AuthMethod() == identity.MethodJWTCookie {
			var validFor time.Duration
			if req.RememberMe {
				if exp, err := time.Parse(time.RFC3339, res.Token.ExpiresAt); err == nil {
					validFor = time.Until(exp)
				}
			}
			ccfg := s.server.Configuration().IdentityMap.GetCookiesConfig()
			setAuthCookie(w, ccfg, res.Token.AccessToken, validFor)
		}
		omitCookieAccessToken(ctx, res, authorization)
		marshal.WriteJSON(w, r, res)
	}
}

// omitCookieAccessToken drops the token from the response of a cookie
// session, which never reads it: the cookie that carries it is HttpOnly.
// A request with an Authorization header uses the token itself and keeps it.
func omitCookieAccessToken(ctx context.Context, res *pb.UserTokenResponse, authorization string) {
	if res == nil || res.Token == nil || authorization != "" {
		return
	}
	if authctx.FromContext(ctx).AuthMethod() == identity.MethodJWTCookie {
		res.Token.AccessToken = ""
	}
}
