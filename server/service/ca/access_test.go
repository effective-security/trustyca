package ca

import (
	"context"
	"testing"

	"github.com/effective-security/porto/xhttp/identity"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/authctx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// caMethods returns the full names of every method of the CA service, from
// the gRPC service descriptor, so that a new method is covered without a
// change here
func caMethods() []string {
	res := make([]string, 0, len(pb.CA_ServiceDesc.Methods))
	for _, m := range pb.CA_ServiceDesc.Methods {
		res = append(res, "/"+pb.CA_ServiceDesc.ServiceName+"/"+m.MethodName)
	}
	return res
}

// TestService_EveryMethod_Access runs the access check of the interceptor
// on every method of the CA: each declares its roles and scopes, the
// trusted service identities of the backend listener (RA, CIS, admin) pass
// with any request, and a guest or a user without an org does not
func TestService_EveryMethod_Access(t *testing.T) {
	t.Parallel()
	authorizer := newFakeAuthorizer()
	guest := authctx.NewTrustyCtx(context.Background(), identity.NewRequestContext(
		identity.NewIdentity(identity.GuestRoleName, "", "", nil, "", "", identity.MethodNone), "/test"))
	noOrg := testCtx("42", "")

	methods := caMethods()
	require.NotEmpty(t, methods)
	for _, method := range methods {
		info := pb.GetMethodInfo(method)
		require.NotNil(t, info, "%s declares its method info", method)
		require.NotEmpty(t, info.AllowedRoles, "%s declares allowed_roles", method)
		require.NotEmpty(t, info.Scopes, "%s declares the scopes of an API key", method)
		require.NotNil(t, info.Allocator, method)

		for _, role := range []string{"trustyca-ra", "trustyca-aia", "trustyca-admin"} {
			err := authctx.CheckAccess(serviceCtx(role), authorizer, info.Allocator(), method)
			assert.NoError(t, err, "%s for %s", method, role)
		}
		err := authctx.CheckAccess(guest, authorizer, info.Allocator(), method)
		assert.Error(t, err, "%s for a guest", method)
		err = authctx.CheckAccess(noOrg, authorizer, info.Allocator(), method)
		assert.Error(t, err, "%s for a user without an org", method)
	}
}
