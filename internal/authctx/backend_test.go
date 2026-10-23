package authctx_test

import (
	"context"
	"testing"

	"github.com/effective-security/porto/xhttp/identity"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/authctx"
	"github.com/effective-security/trustyca/privpb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// forwardedContextHeader is the gRPC metadata the WFE forwards the caller's
// context in
const forwardedContextHeader = "x-trustyca-context"

// serviceIdentityCtx returns the context of a call the backend listener
// authenticated with the TLS role
func serviceIdentityCtx(role, method string) context.Context {
	uid := identity.NewIdentity(role, "spiffe://trustyca/"+role, "", nil, "", "", identity.MethodCertificate)
	return identity.AddToContext(context.Background(), identity.NewRequestContext(uid, method))
}

// forwardedFrom returns the context of a call of the peer role that
// forwards the context of the user the WFE authenticated
func forwardedFrom(t *testing.T, role, method string, user identity.Identity) context.Context {
	t.Helper()
	wfe := authctx.NewTrustyCtx(context.Background(), identity.NewRequestContext(user, "/wfe"))
	md, ok := metadata.FromOutgoingContext(wfe)
	require.True(t, ok)
	return metadata.NewIncomingContext(serviceIdentityCtx(role, method), md)
}

func TestNewAuthUnaryBackendInterceptor(t *testing.T) {
	t.Parallel()
	interceptor := authctx.NewAuthUnaryBackendInterceptor(authctx.NewAuthorizer(specGrants()))
	signMethod := privpb.Backend_SignCertificate_FullMethodName
	// the backend receives the privpb counterpart of a CA request, with the
	// org of the caller's token
	signReq := &privpb.SignCertificateRequest{
		OrgID: orgID().String(),
	}
	// call runs the interceptor and returns the context the handler sees,
	// or nil when the handler is not called
	call := func(ctx context.Context, method string, req any) (authctx.TrustyCtx, error) {
		t.Helper()
		var seen authctx.TrustyCtx
		_, err := interceptor(ctx, req, &grpc.UnaryServerInfo{FullMethod: method}, func(ctx context.Context, _ any) (any, error) {
			seen = authctx.FromContext(ctx)
			return nil, nil
		})
		return seen, err
	}

	// without a forwarded context, the identity the listener authenticated:
	// a service caller over mTLS acts under its own role and names the org
	// of every request
	tctx, err := call(serviceIdentityCtx("trustyca-ra", signMethod), signMethod, signReq)
	require.NoError(t, err)
	assert.Equal(t, "trustyca-ra", tctx.AppRole())
	assert.True(t, tctx.OrgID().IsZero())
	assert.False(t, tctx.IsAPIKey())
	assert.Equal(t, identity.MethodCertificate, tctx.AuthMethod())
	assert.Equal(t, signMethod, tctx.Target())
	// the peer without a forwarded context acts as itself too
	tctx, err = call(serviceIdentityCtx(authctx.PeerRoleName, signMethod), signMethod, signReq)
	require.NoError(t, err)
	assert.Equal(t, authctx.PeerRoleName, tctx.AppRole())
	// a caller without an identity is a guest
	tctx, err = call(context.Background(), signMethod, signReq)
	require.NoError(t, err)
	assert.Equal(t, "guest", tctx.AppRole())
	assert.True(t, tctx.OrgID().IsZero())

	// the WFE forwards the context of the end user it authenticated: the
	// call runs as that user, authorized for the pb.CA method of the same
	// name (SignCertificate: User)
	user := identityFor(userID().String(), orgID().String(), pb.Role_User.String())
	tctx, err = call(forwardedFrom(t, authctx.PeerRoleName, signMethod, user), signMethod, signReq)
	require.NoError(t, err)
	assert.Equal(t, "user", tctx.AppRole())
	assert.Equal(t, orgID().UInt64(), tctx.OrgID().UInt64())
	assert.Equal(t, userID().UInt64(), tctx.UserID().UInt64())
	assert.Equal(t, userID().String()+"@example.com", tctx.Email())
	assert.Equal(t, "User "+userID().String(), tctx.Name())
	assert.Equal(t, pb.Role_User, tctx.OrgRole())
	assert.Equal(t, identity.MethodJWT, tctx.AuthMethod())
	assert.Equal(t, "/wfe", tctx.Target())

	// a forwarded user without the role of the method is refused before
	// the handler: a Viewer may not sign, and may read a CRL
	viewer := identityFor(viewerID().String(), orgID().String(), pb.Role_Viewer.String())
	tctx, err = call(forwardedFrom(t, authctx.PeerRoleName, signMethod, viewer), signMethod, signReq)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "forbidden:")
	assert.Nil(t, tctx)
	tctx, err = call(forwardedFrom(t, authctx.PeerRoleName, pb.CA_GetCRL_FullMethodName, viewer), pb.CA_GetCRL_FullMethodName, &pb.GetCrlRequest{IKID: "0a"})
	require.NoError(t, err)
	assert.Equal(t, viewerID().UInt64(), tctx.UserID().UInt64())
	// a forwarded user of another org than the request's is refused
	tctx, err = call(forwardedFrom(t, authctx.PeerRoleName, signMethod, user), signMethod, &privpb.SignCertificateRequest{OrgID: otherOrgID().String()})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "org mismatch")
	assert.Nil(t, tctx)
	// a forwarded user may not reach the Admin API
	adminMethod := privpb.Admin_ListOrgs_FullMethodName
	tctx, err = call(forwardedFrom(t, authctx.PeerRoleName, adminMethod, user), adminMethod, &privpb.ListOrgsRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "forbidden: access denied")
	assert.Nil(t, tctx)

	// another service identity cannot speak for a user: its forwarded
	// context is ignored and it acts as itself
	tctx, err = call(forwardedFrom(t, "trustyca-aia", signMethod, user), signMethod, signReq)
	require.NoError(t, err)
	assert.Equal(t, "trustyca-aia", tctx.AppRole())
	assert.True(t, tctx.UserID().IsZero())

	// a forwarded context that does not parse fails the call
	bad := metadata.NewIncomingContext(serviceIdentityCtx(authctx.PeerRoleName, signMethod), metadata.Pairs(forwardedContextHeader, "{"))
	tctx, err = call(bad, signMethod, signReq)
	assert.EqualError(t, err, "unauthorized: invalid forwarded context")
	assert.Nil(t, tctx)
}
