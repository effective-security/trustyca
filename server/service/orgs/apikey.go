package orgs

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/effective-security/porto/xhttp/httperror"
	pb "github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/authctx"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/dataprotection"
	"golang.org/x/crypto/pbkdf2"
	"google.golang.org/grpc/codes"
)

const (
	defaultAPIKeyExpiry = 90 * 24 * time.Hour
)

// CreateAPIKey creates a new API key in the org selected in the token,
// optionally restricted to a project.
// The public key is encoded as sk_<OrgID>_<protectedKeyID>, where the key ID
// is protected with the dataprotection key (TODO: per org key); the secret
// is stored protected and returned to the caller only once.
func (s *Service) CreateAPIKey(ctx context.Context, req *pb.CreateAPIKeyRequest) (*pb.APIKey, error) {
	orgID, err := tokenOrg(ctx)
	if err != nil {
		return nil, err
	}
	trustyctx := authctx.FromContext(ctx)
	if req.Label == "" {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "label is required")
	}

	scopes := req.Scopes
	if len(scopes) == 0 {
		scopes = authctx.DefaultAPIKeyScopes
	}
	for _, scope := range scopes {
		if !authctx.IsKnownScope(scope) {
			return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "unknown scope: %s", scope)
		}
	}

	projectID, err := parseOptionalID(ctx, req.ProjectID, "project ID")
	if err != nil {
		return nil, err
	}
	// a project scoped key must reference an active project of the org
	_, err = s.getProject(ctx, orgID, projectID)
	if err != nil {
		return nil, err
	}

	m := model.APIKey{
		ID:        s.db.NextID(),
		OrgID:     orgID,
		ProjectID: projectID,
		Label:     req.Label,
		Scopes:    scopes,
		Status:    pb.ItemStatus_Active,
		Metadata: xdb.Metadata{
			"created_by": trustyctx.Email(),
		},
	}

	if req.ExpiresAt != "" {
		m.ExpiresAt = xdb.ParseTime(req.ExpiresAt)
		if m.ExpiresAt.IsZero() || m.ExpiresAt.UTC().Before(time.Now()) {
			return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid expiration time")
		}
	} else {
		m.ExpiresAt = xdb.Time(time.Now().Add(defaultAPIKeyExpiry))
	}

	// the key carries the org ID in clear and the protected key ID
	protectedKeyID, err := dataprotection.ProtectObject(ctx, s.dataprotection, m.ID.String())
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "failed to protect key")
	}
	m.Key = fmt.Sprintf("sk_%s_%s", orgID, protectedKeyID)
	secret := strongRandom(32)
	m.Secret, err = dataprotection.ProtectObject(ctx, s.dataprotection, secret)
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "failed to protect secret")
	}

	a, err := s.db.RegisterAPIKey(ctx, &m)
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "failed to register API key")
	}
	s.event(ctx, orgID, projectID, a.ID, pb.EventType_APIKeyCreated,
		fmt.Sprintf("API key %s created", a.Label))

	res := a.Pb()
	// the secret is returned only once
	res.Secret = secret
	return res, nil
}

// ListAPIKeys lists the API keys of the org selected in the token, or of a
// project when ProjectID is set
func (s *Service) ListAPIKeys(ctx context.Context, req *pb.ListAPIKeysRequest) (*pb.APIKeysResponse, error) {
	orgID, err := tokenOrg(ctx)
	if err != nil {
		return nil, err
	}
	projectID, err := parseOptionalID(ctx, req.ProjectID, "project ID")
	if err != nil {
		return nil, err
	}

	lreq := &query.ListAPIKeysRequest{
		OrgID:     orgID.UInt64(),
		ProjectID: projectID.UInt64(),
		Status:    req.Status,
		Limit:     defaultListLimit,
	}

	lres, err := s.db.ListAPIKeys(ctx, lreq)
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "failed to list API keys")
	}
	return lres.Pb(), nil
}

// DeleteAPIKey deletes an API key of the org selected in the token.
// When ProjectID is set it must match the project of the key.
func (s *Service) DeleteAPIKey(ctx context.Context, req *pb.APIKeyRequest) (*pb.RecordsResult, error) {
	orgID, err := tokenOrg(ctx)
	if err != nil {
		return nil, err
	}
	id, err := xdb.ParseID(req.ID)
	if err != nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid ID")
	}

	key, err := s.db.GetAPIKey(ctx, orgID.UInt64(), id.UInt64())
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "unable to get API key")
	}
	if req.ProjectID != "" && key.ProjectID.String() != req.ProjectID {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.NotFound, "API key not found in the project")
	}

	res, err := s.db.DeleteAPIKey(ctx, orgID.UInt64(), id.UInt64())
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "unable to delete API key")
	}
	s.event(ctx, orgID, key.ProjectID, key.ID, pb.EventType_APIKeyDeleted,
		fmt.Sprintf("API key %s deleted", key.Label))

	return &pb.RecordsResult{Deleted: res}, nil
}

func strongRandom(byteLength int) string {
	passphrase := certutil.Random(64)
	salt := certutil.Random(32)
	secret := pbkdf2.Key(passphrase, salt, 10, 32, sha256.New)
	return base64.RawURLEncoding.EncodeToString(secret)[:byteLength]
}
