package auth

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/effective-security/porto/restserver"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/porto/xhttp/identity"
	"github.com/effective-security/porto/xhttp/marshal"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/authctx"
	"github.com/effective-security/x/values"
	"github.com/effective-security/xpki/jwt"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/emptypb"
)

// UserinfoHandler returns handler for returning the user info
func (s *Service) UserinfoHandler() restserver.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ restserver.Params) {
		caller := identity.FromRequest(r).Identity()
		claims := caller.Claims()
		//logger.KV(xlog.DEBUG, "claims", claims)

		marshal.WritePlainJSON(w, http.StatusOK, claims, marshal.PrettyPrint)
	}
}

// GetUserToken returns the user token info
func (s *Service) GetUserToken(ctx context.Context, _ *emptypb.Empty) (*pb.UserTokenResponse, error) {
	caller := identity.FromContext(ctx).Identity()

	var claims jwt.Claims
	mapclaims := caller.Claims()
	err := mapclaims.To(&claims)
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "request failed")
	}

	res := &pb.UserTokenResponse{
		Token: &pb.Token{
			TokenType: caller.TokenType(),
			// If the authentication method is JWT Cookie, do not return the access token
			AccessToken: values.Select(caller.AuthMethod() == identity.MethodJWTCookie, "", caller.AccessToken()),
			ExpiresAt:   mapclaims.TimeVal("exp").Format(time.RFC3339),
			IssuedAt:    mapclaims.TimeVal("iat").Format(time.RFC3339),
			Issuer:      mapclaims.String("iss"),
			Audience:    mapclaims.String("aud"),
			Provider:    pb.IDP_Enum_Value[mapclaims.String("provider")],
		},
		UserInfo: &pb.UserInfo{
			ID:            claims.Subject,
			Name:          claims.Name,
			Email:         claims.Email,
			EmailVerified: claims.EmailVerified,
			Role:          caller.Role(),
			OrgID:         mapclaims.String(authctx.ClaimOrg),
			OrgRole:       mapclaims.String(authctx.ClaimOrgRole),
			OrgRoleSource: mapclaims.String(authctx.ClaimOrgRoleSource),
		},
	}
	if claims.Cnf != nil {
		res.Token.Jkt = claims.Cnf.Jkt
	}
	return res, nil
}

// UserTokenHandler returns UserTokenResponse
func (s *Service) UserTokenHandler() restserver.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ restserver.Params) {
		res, err := s.GetUserToken(r.Context(), nil)
		if err != nil {
			marshal.WriteJSON(w, r, err)
			return
		}
		marshal.WriteJSON(w, r, &res)
	}
}

// Caller returns the status of the caller.
func (s *Service) Caller(ctx context.Context, _ *emptypb.Empty) (*pb.CallerStatusResponse, error) {
	callerCtx := identity.FromContext(ctx)
	caller := callerCtx.Identity()

	res := &pb.CallerStatusResponse{
		Subject: caller.Subject(),
		Role:    caller.Role(),
	}

	cl := caller.Claims()
	if len(cl) > 0 {
		res.Claims = make([]*pb.KVPair, 0, len(cl))
		for k := range cl {
			res.Claims = append(res.Claims, &pb.KVPair{Key: k, Value: cl.String(k)})
		}
	}

	return res, nil
}

func (s *Service) callerStatus() restserver.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ restserver.Params) {
		callerCtx := identity.FromRequest(r)
		caller := callerCtx.Identity()

		res := &pb.CallerStatusResponse{
			Subject: caller.Subject(),
			Role:    caller.Role(),
		}

		cl := caller.Claims()
		if len(cl) > 0 {
			res.Claims = make([]*pb.KVPair, 0, len(cl))
			for k := range cl {
				res.Claims = append(res.Claims, &pb.KVPair{Key: k, Value: cl.String(k)})
			}
		}

		accept := r.Header.Get(header.Accept)
		if accept == "" || strings.EqualFold(accept, header.ApplicationJSON) {
			marshal.WriteJSON(w, r, res)
		} else {
			w.Header().Set(header.ContentType, header.TextPlain)
			// TODO: print
			// res.Print(w)
			marshal.WriteJSON(w, r, res)
		}
	}
}

// RevokeToken revokes the user token
func (s *Service) RevokeToken(ctx context.Context, _ *emptypb.Empty) (*emptypb.Empty, error) {
	err := s.revoke(ctx)
	if err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}

func (s *Service) revoke(ctx context.Context) error {
	ictx := identity.FromContext(ctx)
	caller := ictx.Identity()
	mapclaims := caller.Claims()
	revocation := s.JwtParser.GetRevocation()
	if revocation == nil {
		return httperror.NewGrpcFromCtx(ctx, codes.Unimplemented, "revocation not supported")
	}

	err := revocation.Revoke(ctx, caller.AccessToken(), mapclaims)
	if err != nil {
		return httperror.WrapWithCtx(ctx, err, "request failed")
	}

	// TODO: events
	// email := mapclaims.String("email")
	// evt := &model.Event{
	// 	Type:        pb.EventType_TokenRevoked,
	// 	Email:       xdb.NULLString(email),
	// 	Source:      xdb.NULLString(ictx.Target()),
	// 	Title:       "Revoked token",
	// 	Description: xdb.NULLString(fmt.Sprintf("User %s revoked token: %s", mapclaims.String("sub"), mapclaims.String("jti"))),
	// }

	// if id := mapclaims.UInt64("org"); id > 0 {
	// 	evt.OrgID = xdb.NewID(id)
	// }

	// s.db.TryCreateEvent(evt)

	return nil
}

// RevokeTokenHandler returns handler for revoking the user token
func (s *Service) RevokeTokenHandler() restserver.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ restserver.Params) {
		ctx := r.Context()
		ccfg := s.server.Configuration().IdentityMap.GetCookiesConfig()
		resetAuthCookie(w, ccfg)

		err := s.revoke(ctx)
		if err != nil {
			marshal.WriteJSON(w, r, httperror.Wrap(err, "request failed").WithContext(ctx))
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// GetAllowedMethods returns the allowed methods for the caller
func (s *Service) GetAllowedMethods(ctx context.Context, req *emptypb.Empty) (*pb.ServiceAccessInfo, error) {
	return authctx.GetAllowedMethods(ctx, s.authorizer)
}

// GetCallerScope returns the caller's resolved scope and the method access rules
func (s *Service) GetCallerScope(ctx context.Context, req *emptypb.Empty) (*pb.CallerScope, error) {
	return authctx.GetCallerScope(ctx, s.authorizer)
}
