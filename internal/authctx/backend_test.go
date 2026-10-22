package authctx_test

import (
	"context"
	"testing"

	"github.com/effective-security/porto/xhttp/identity"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/authctx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// forwardedContextHeader is the gRPC metadata the WFE forwards the caller's
// context in
const forwardedContextHeader = "x-trustyca-context"

func TestNewAuthUnaryBackendInterceptor(t *testing.T) {
	t.Parallel()
	interceptor := authctx.NewAuthUnaryBackendInterceptor()
	info := &grpc.UnaryServerInfo{FullMethod: pb.CA_GetCRL_FullMethodName}
	capture := func(ctx context.Context, _ any) (any, error) {
		return authctx.FromContext(ctx), nil
	}
	call := func(ctx context.Context) authctx.TrustyCtx {
		t.Helper()
		res, err := interceptor(ctx, nil, info, capture)
		require.NoError(t, err)
		return res.(authctx.TrustyCtx)
	}

	// without a forwarded context, the identity the listener authenticated:
	// a service caller over mTLS acts under its own role and names the org
	// of every request
	ra := identity.NewIdentity("trustyca-ra", "spiffe://trustyca/ra", "", nil, "", "", identity.MethodCertificate)
	raCtx := identity.AddToContext(context.Background(), identity.NewRequestContext(ra, info.FullMethod))
	tctx := call(raCtx)
	assert.Equal(t, "trustyca-ra", tctx.AppRole())
	assert.True(t, tctx.OrgID().IsZero())
	assert.False(t, tctx.IsAPIKey())
	assert.Equal(t, identity.MethodCertificate, tctx.AuthMethod())
	assert.Equal(t, info.FullMethod, tctx.Target())
	// a caller without an identity is a guest
	tctx = call(context.Background())
	assert.Equal(t, "guest", tctx.AppRole())
	assert.True(t, tctx.OrgID().IsZero())

	// the context the WFE forwards for the end user it authenticated wins
	// over the identity of the forwarding peer
	user := identity.NewIdentity("user", "42", "1", map[string]any{
		"sub":                "42",
		"email":              "user@example.com",
		"name":               "User",
		authctx.ClaimOrg:     "1",
		authctx.ClaimOrgRole: pb.Role_Admin.String(),
	}, "tok", "Bearer", identity.MethodJWT)
	wfe := authctx.NewTrustyCtx(context.Background(), identity.NewRequestContext(user, "/wfe"))
	md, ok := metadata.FromOutgoingContext(wfe)
	require.True(t, ok)
	tctx = call(metadata.NewIncomingContext(raCtx, md))
	assert.Equal(t, "user", tctx.AppRole())
	assert.Equal(t, uint64(1), tctx.OrgID().UInt64())
	assert.Equal(t, "42", tctx.UserID().String())
	assert.Equal(t, "user@example.com", tctx.Email())
	assert.Equal(t, "User", tctx.Name())
	assert.Equal(t, pb.Role_Admin, tctx.OrgRole())
	assert.Equal(t, identity.MethodJWT, tctx.AuthMethod())
	assert.Equal(t, "/wfe", tctx.Target())

	// a forwarded context that does not parse sets no identity: the call
	// fails closed downstream instead of acting as the peer
	tctx = call(metadata.NewIncomingContext(raCtx, metadata.Pairs(forwardedContextHeader, "{")))
	assert.Empty(t, tctx.AppRole())
	assert.True(t, tctx.OrgID().IsZero())
	assert.True(t, tctx.UserID().IsZero())
}
