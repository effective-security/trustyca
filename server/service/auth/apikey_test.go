package auth_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/authctx"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/server/service/auth"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/dataprotection"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"
)

// testAPIKey is an API key as orgs.CreateAPIKey stores it, with its secret
type testAPIKey struct {
	ID     xdb.ID
	Key    string
	Secret string
}

// registerAPIKey stores an API key of the org, restricted to the project
// when one is given
func registerAPIKey(t *testing.T, orgID, projectID xdb.ID, expiresAt time.Time) *testAPIKey {
	t.Helper()
	ctx := t.Context()
	keyID := testDb.NextID()
	protectedID, err := dataprotection.ProtectObject(ctx, testDp, keyID.String())
	require.NoError(t, err)
	secret := certutil.RandomString(32)
	protectedSecret, err := dataprotection.ProtectObject(ctx, testDp, secret)
	require.NoError(t, err)
	key, err := testDb.RegisterAPIKey(ctx, &model.APIKey{
		ID:        keyID,
		OrgID:     orgID,
		ProjectID: projectID,
		Key:       fmt.Sprintf("sk_%s_%s", orgID, protectedID),
		Secret:    protectedSecret,
		Label:     "ci",
		Scopes:    authctx.DefaultAPIKeyScopes,
		Status:    pb.ItemStatus_Active,
		ExpiresAt: xdb.Time(expiresAt),
	})
	require.NoError(t, err)
	return &testAPIKey{ID: keyID, Key: key.Key, Secret: secret}
}

// apiKeyAuthorization returns the Authorization value of the key for the
// timestamp: HMAC-SHA256 of the method and timestamp under the secret
func apiKeyAuthorization(keyStr, secret, timestamp string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(pb.Auth_AuthenticateAPIKey_FullMethodName))
	mac.Write([]byte(timestamp))
	return "APIKey " + keyStr + ":" + base64.URLEncoding.EncodeToString(mac.Sum(nil))
}

// apiKeyCtx returns the gRPC context of an AuthenticateAPIKey call with the
// metadata pairs
func apiKeyCtx(t *testing.T, kv ...string) context.Context {
	return metadata.NewIncomingContext(t.Context(), metadata.Pairs(kv...))
}

// errorOf returns the code and message of an httperror; its text also
// carries the request ID
func errorOf(t *testing.T, err error) string {
	t.Helper()
	var he *httperror.Error
	require.True(t, errors.As(err, &he), "an httperror: %v", err)
	return he.Code + ": " + he.Message
}

// causeOf returns the code and message of the cause of a refused API key,
// which the service sends as one "failed to authenticate API key" error
func causeOf(t *testing.T, err error) string {
	t.Helper()
	var he *httperror.Error
	require.True(t, errors.As(err, &he), "an httperror: %v", err)
	require.NotNil(t, he.Cause(), "the cause of %v", err)
	return errorOf(t, he.Cause())
}

func Test_AuthenticateAPIKey(t *testing.T) {
	t.Parallel()
	service := testServer.Service(auth.ServiceName).(*auth.Service)
	_, org := newOwnerOrg(t)
	project := newProject(t, org.ID)
	orgKey := registerAPIKey(t, org.ID, xdb.ID(0), time.Now().Add(time.Hour))
	projectKey := registerAPIKey(t, org.ID, project.ID, time.Now().Add(time.Hour))
	now := time.Now().UTC().Format(time.RFC3339)

	t.Run("metadata", func(t *testing.T) {
		t.Parallel()
		_, err := service.AuthenticateAPIKey(t.Context(), &emptypb.Empty{})
		assert.EqualError(t, err, "bad_request: missing metadata")
		_, err = service.AuthenticateAPIKey(apiKeyCtx(t, "date", now), &emptypb.Empty{})
		assert.EqualError(t, err, "bad_request: missing authorization header")
		_, err = service.AuthenticateAPIKey(apiKeyCtx(t, "authorization", "APIKey x:y"), &emptypb.Empty{})
		assert.EqualError(t, err, "bad_request: missing timestamp")
		_, err = service.AuthenticateAPIKey(apiKeyCtx(t, "authorization", "Bearer x", "timestamp", now), &emptypb.Empty{})
		assert.EqualError(t, err, "bad_request: invalid authorization format")
	})

	t.Run("refused", func(t *testing.T) {
		t.Parallel()
		otherOrgKey := "sk_" + testDb.NextID().String() + orgKey.Key[len("sk_")+len(org.ID.String()):]
		protectedName, err := dataprotection.ProtectObject(t.Context(), testDp, "not-an-id")
		require.NoError(t, err)
		unknownID, err := dataprotection.ProtectObject(t.Context(), testDp, testDb.NextID().String())
		require.NoError(t, err)
		expired := registerAPIKey(t, org.ID, xdb.ID(0), time.Now().Add(-time.Minute))

		tcs := []struct {
			name          string
			authorization string
			timestamp     string
			cause         string
		}{
			{"timestamp", apiKeyAuthorization(orgKey.Key, orgKey.Secret, "now"), "now", "bad_request: invalid or expired timestamp"},
			{"old", apiKeyAuthorization(orgKey.Key, orgKey.Secret, now), time.Now().Add(-time.Hour).UTC().Format(time.RFC3339), "bad_request: invalid or expired timestamp"},
			{"future", apiKeyAuthorization(orgKey.Key, orgKey.Secret, now), time.Now().Add(time.Hour).UTC().Format(time.RFC3339), "bad_request: timestamp is in the future"},
			{"credentials", "APIKey " + orgKey.Key, now, "bad_request: invalid authorization credentials"},
			{"prefix", apiKeyAuthorization("pk_"+orgKey.Key[len("sk_"):], orgKey.Secret, now), now, "forbidden: invalid API key"},
			{"org", apiKeyAuthorization("sk_org_"+orgKey.Key, orgKey.Secret, now), now, "forbidden: invalid API key"},
			{"protected", apiKeyAuthorization(fmt.Sprintf("sk_%s_nope", org.ID), orgKey.Secret, now), now, "forbidden: invalid API key"},
			{"id", apiKeyAuthorization(fmt.Sprintf("sk_%s_%s", org.ID, protectedName), orgKey.Secret, now), now, "forbidden: invalid API key"},
			{"unknown", apiKeyAuthorization(fmt.Sprintf("sk_%s_%s", org.ID, unknownID), orgKey.Secret, now), now, "forbidden: invalid API key"},
			{"other_org", apiKeyAuthorization(otherOrgKey, orgKey.Secret, now), now, "forbidden: invalid API key"},
			{"expired", apiKeyAuthorization(expired.Key, expired.Secret, now), now, "forbidden: invalid API key"},
			{"signature", apiKeyAuthorization(orgKey.Key, "another secret", now), now, "forbidden: invalid HMAC signature"},
		}
		for _, tc := range tcs {
			_, err := service.AuthenticateAPIKey(apiKeyCtx(t, "authorization", tc.authorization, "timestamp", tc.timestamp), &emptypb.Empty{})
			require.Error(t, err, tc.name)
			assert.Equal(t, "forbidden: failed to authenticate API key", errorOf(t, err), tc.name)
			assert.Equal(t, tc.cause, causeOf(t, err), tc.name)
		}
	})

	t.Run("token", func(t *testing.T) {
		t.Parallel()
		res, err := service.AuthenticateAPIKey(apiKeyCtx(t, "authorization", apiKeyAuthorization(orgKey.Key, orgKey.Secret, now), "date", now), &emptypb.Empty{})
		require.NoError(t, err)
		require.NotNil(t, res.Token)
		assert.NotEmpty(t, res.Token.AccessToken)
		require.NotNil(t, res.UserInfo)
		assert.Equal(t, org.ID.String(), res.UserInfo.OrgID)
		assert.Equal(t, pb.Role_APIKey.String(), res.UserInfo.OrgRole)
		assert.Equal(t, orgKey.ID.String()+"+apikey@trustyca.com", res.UserInfo.Email)

		// a key restricted to a project of the org
		res, err = service.AuthenticateAPIKey(apiKeyCtx(t, "authorization", apiKeyAuthorization(projectKey.Key, projectKey.Secret, now), "timestamp", now), &emptypb.Empty{})
		require.NoError(t, err)
		assert.NotEmpty(t, res.Token.AccessToken)
	})

	t.Run("project", func(t *testing.T) {
		t.Parallel()
		inactive := newProject(t, org.ID)
		key := registerAPIKey(t, org.ID, inactive.ID, time.Now().Add(time.Hour))
		_, err := testDb.UpdateProject(t.Context(), &query.UpdateProjectRequest{
			ID:     inactive.ID.UInt64(),
			Status: pb.ItemStatus_Inactive,
		})
		require.NoError(t, err)
		_, err = service.AuthenticateAPIKey(apiKeyCtx(t, "authorization", apiKeyAuthorization(key.Key, key.Secret, now), "timestamp", now), &emptypb.Empty{})
		require.Error(t, err)
		assert.Equal(t, "forbidden: project is not available", errorOf(t, err))
	})

	t.Run("handler", func(t *testing.T) {
		t.Parallel()
		h := service.AuthenticateAPIKeyHandler()
		call := func(authorization, date string) *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			r, err := http.NewRequest(http.MethodPost, pb.Auth_AuthenticateAPIKey_FullMethodName, nil)
			require.NoError(t, err)
			if authorization != "" {
				r.Header.Set(header.Authorization, authorization)
			}
			if date != "" {
				r.Header.Set(dateHeader, date)
			}
			h(w, r, nil)
			return w
		}
		w := call("", now)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Equal(t, `{"code":"unauthorized","message":"missing authorization header"}`, w.Body.String())
		w = call(apiKeyAuthorization(orgKey.Key, orgKey.Secret, now), "")
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Equal(t, `{"code":"unauthorized","message":"missing date header"}`, w.Body.String())
		w = call("Bearer "+orgKey.Key, now)
		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Contains(t, w.Body.String(), `"message":"failed to authenticate API key"`)
		w = call(apiKeyAuthorization(orgKey.Key, orgKey.Secret, now), now)
		assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
	})
}
