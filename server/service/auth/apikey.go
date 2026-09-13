package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/effective-security/porto/restserver"
	"github.com/effective-security/porto/xhttp/correlation"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/porto/xhttp/marshal"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/authctx"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/dataprotection"
	"github.com/effective-security/xpki/jwt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"
)

// AuthenticateAPIKeyHandler is the handler for the AuthenticateAPIKey endpoint
// It is used to authenticate API keys.
// It expects the following headers:
// Date: <timestamp>
// Authorization: APIKey <key_id>:<signature>
func (s *Service) AuthenticateAPIKeyHandler() restserver.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ restserver.Params) {
		authzHeader := r.Header.Get(header.Authorization)
		dateHeader := r.Header.Get("date")
		if authzHeader == "" {
			marshal.WriteJSON(w, r, httperror.Unauthorized("missing authorization header"))
			return
		}
		if dateHeader == "" {
			marshal.WriteJSON(w, r, httperror.Unauthorized("missing date header"))
			return
		}

		res, err := s.authenticateAPIKey(r.Context(), authzHeader, dateHeader)
		if err != nil {
			marshal.WriteJSON(w, r, err)
			return
		}

		marshal.WriteJSON(w, r, &res)
	}
}

// AuthenticateAPIKey authenticates an API key and returns a user token response
func (s *Service) AuthenticateAPIKey(ctx context.Context, req *emptypb.Empty) (*pb.UserTokenResponse, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "missing metadata")
	}

	authHeaders := md.Get("authorization")
	if len(authHeaders) == 0 {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "missing authorization header")
	}

	timestamp := md.Get("timestamp")
	if len(timestamp) == 0 {
		timestamp = md.Get("date")
	}
	if len(timestamp) == 0 {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "missing timestamp")
	}

	// Extract API Key ID and Signature
	var authHeader string
	for _, h := range authHeaders {
		if strings.HasPrefix(h, "APIKey ") {
			authHeader = h
		}
	}
	if authHeader == "" {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid authorization format")
	}

	return s.authenticateAPIKey(ctx, authHeader, timestamp[0])
}

func (s *Service) authenticateAPIKey(ctx context.Context, authHeader, timestamp string) (*pb.UserTokenResponse, error) {
	ctx = correlation.WithID(ctx)
	key, err := s.validateHMAC(ctx, pb.Auth_AuthenticateAPIKey_FullMethodName, authHeader, timestamp)
	if err != nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.PermissionDenied, "failed to authenticate API key").WithCause(err)
	}

	// TODO: add a config option for the email domain
	email := fmt.Sprintf("%s+apikey@trustyca.com", key.ID)
	// the token identifies the key, its org and optional project; the
	// authorizer checks the key scopes against the method scopes
	claims := jwt.MapClaims{
		authctx.ClaimOrg:     key.OrgID,
		authctx.ClaimOrgRole: pb.Role_APIKey.String(),
		authctx.ClaimScope:   key.Scopes,
		"sub":                key.ID,
		"email":              email,
		"provider":           "apikey",
		"iss":                s.JwtSigner.Issuer(),
		"aud":                s.getAudience(false),
		"nonce":              certutil.RandomString(8),
	}
	if key.ProjectID != "" {
		projectID, err := xdb.ParseID(key.ProjectID)
		if err != nil {
			return nil, httperror.NewGrpcFromCtx(ctx, codes.Internal, "invalid project ID of the key")
		}
		project, err := s.db.GetProject(ctx, projectID.UInt64())
		if err != nil {
			return nil, httperror.WrapWithCtx(ctx, err, "failed to get project")
		}
		if project.OrgID.String() != key.OrgID || project.Status != pb.ItemStatus_Active {
			return nil, httperror.NewGrpcFromCtx(ctx, codes.PermissionDenied, "project is not available")
		}
		claims[authctx.ClaimProject] = key.ProjectID
	}

	// give only one hour
	jwt.SetClaimsExpiration(claims, time.Hour)

	tokenStr, err := s.JwtSigner.Sign(ctx, claims)
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "failed to sign JWT")
	}

	res := &pb.UserTokenResponse{
		Token: &pb.Token{
			TokenType:   "Bearer",
			AccessToken: tokenStr,
			ExpiresAt:   claims.TimeVal("exp").Format(time.RFC3339),
			IssuedAt:    claims.TimeVal("iat").Format(time.RFC3339),
			Issuer:      claims.String("iss"),
			Audience:    claims.String("aud"),
			Provider:    pb.IDP_Undefined.Parse(claims.String("provider")),
		},
		UserInfo: &pb.UserInfo{
			ID:            key.ID,
			Name:          key.Label,
			Email:         email,
			OrgID:         key.OrgID,
			OrgRole:       pb.Role_APIKey.String(),
			OrgRoleSource: authctx.RoleSourceDirect,
			Role:          "user", // App role, not Org role
		},
	}
	return res, nil
}

func (s *Service) validateHMAC(ctx context.Context, method, authHeader, timestamp string) (*pb.APIKey, error) {
	// Prevent replay attacks (5 min tolerance)
	reqTime, err := time.Parse(time.RFC3339, timestamp)
	if err != nil || time.Since(reqTime) > 5*time.Minute {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid or expired timestamp")
	}
	if time.Until(reqTime) > 5*time.Minute {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "timestamp is in the future")
	}

	authParts := strings.SplitN(authHeader, " ", 2)
	if len(authParts) != 2 {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid authorization header")
	}

	if !strings.EqualFold(authParts[0], "APIKey") {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid authorization scheme")
	}

	credentials := strings.SplitN(authParts[1], ":", 2)
	if len(credentials) != 2 {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid authorization credentials")
	}
	keyStr, receivedSignature := strings.TrimSpace(credentials[0]), strings.TrimSpace(credentials[1])

	key, err := s.findAPIKey(ctx, keyStr)
	if err != nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.PermissionDenied, "invalid API key").WithCause(err)
	}

	// Recompute expected signature
	expectedSignature := generateHMACSignature(method, timestamp, key.Secret)

	// Compare signatures
	if !hmac.Equal([]byte(receivedSignature), []byte(expectedSignature)) {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.PermissionDenied, "invalid HMAC signature")
	}

	ev := &model.Event{
		Type:   pb.EventType_APIKeyLogin,
		Title:  fmt.Sprintf("API key %s authenticated", key.Label),
		Source: xdb.NULLString("APIKey"),
	}
	_ = ev.ReferenceID.Set(key.ID)
	_ = ev.OrgID.Set(key.OrgID)
	_ = ev.ProjectID.Set(key.ProjectID)
	s.db.TryCreateEvent(ev)

	return key, nil
}

func (s *Service) findAPIKey(ctx context.Context, keyStr string) (*pb.APIKey, error) {
	// sk_<OrgID>_<encryptedKeyID>
	parts := strings.SplitN(keyStr, "_", 3)
	if len(parts) != 3 || parts[0] != "sk" {
		logger.ContextKV(ctx, xlog.DEBUG,
			"reason", "invalid_key_format",
			"key_id", keyStr,
			"parts", len(parts),
			"prefix", parts[0],
		)
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid key")
	}

	orgID, err := xdb.ParseID(parts[1])
	if err != nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid key")
	}

	var decryptedKeyID string
	err = dataprotection.UnprotectObject(ctx, s.dataprotection, parts[2], &decryptedKeyID)
	if err != nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.PermissionDenied, "invalid key").WithCause(err)
	}

	keyID, err := xdb.ParseID(decryptedKeyID)
	if err != nil {
		logger.ContextKV(ctx, xlog.DEBUG,
			"reason", "unable_to_parse_api_key_id",
			"key_id", keyStr,
		)
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid key ID")
	}

	m, err := s.db.UseAPIKey(ctx, orgID.UInt64(), keyID.UInt64())
	if err != nil {
		if xdb.IsNotFoundError(err) {
			logger.ContextKV(ctx, xlog.DEBUG,
				"reason", "UseAPIKey",
				"org_id", orgID.String(),
				"key_id", keyID.String(),
				"err", err.Error())
			return nil, httperror.NewGrpcFromCtx(ctx, codes.PermissionDenied, "invalid key").WithCause(err)
		}
		logger.ContextKV(ctx, xlog.ERROR,
			"reason", "UseAPIKey",
			"org_id", orgID.String(),
			"key_id", keyID.String(),
			"err", err.Error())
		return nil, httperror.NewGrpcFromCtx(ctx, codes.PermissionDenied, "invalid key").WithCause(err)
	}

	if m == nil || m.OrgID.UInt64() != orgID.UInt64() {
		logger.ContextKV(ctx, xlog.WARNING,
			"reason", "org_id_mismatch",
			"org_id", orgID.String(),
			"key_id", keyID.String(),
		)
		return nil, httperror.NewGrpcFromCtx(ctx, codes.PermissionDenied, "invalid key")
	}

	if !m.ExpiresAt.IsZero() && m.ExpiresAt.UTC().Before(time.Now()) {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.PermissionDenied, "key expired")
	}

	res := m.Pb()

	// return the secret
	err = dataprotection.UnprotectObject(ctx, s.dataprotection, m.Secret, &res.Secret)
	if err != nil {
		logger.ContextKV(ctx, xlog.ERROR, "reason", "UnprotectOrgObject", "err", err.Error())
		return nil, httperror.NewGrpcFromCtx(ctx, codes.Internal, "unexpected error").WithCause(err)
	}

	return res, nil
}

// signature = HMAC-SHA256(secret, method + url + timestamp + body_hash)
func generateHMACSignature(method, timestamp, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(method))
	h.Write([]byte(timestamp))
	return base64.URLEncoding.EncodeToString(h.Sum(nil))
}
