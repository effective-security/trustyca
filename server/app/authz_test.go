package app

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/effective-security/porto/restserver/authz"
	"github.com/effective-security/porto/xhttp/identity"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/config"
	"github.com/effective-security/trustyca/privpb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

// The identities the backend listener maps from client certificates
// (identity_map.tls of etc/dev/trustyca-config.yaml)
var backendRoles = []string{"trustyca-ra", "trustyca-cis", "trustyca-admin", "trustyca-peer", "trustyca-client", identity.GuestRoleName}

// cisMethods are the only methods of the CA the CIS identity may call: it
// forwards OCSP requests and reads the public revocation data
var cisMethods = map[string]bool{
	pb.CA_SignOCSP_FullMethodName:  true,
	pb.CA_GetCRL_FullMethodName:    true,
	pb.CA_ListRoots_FullMethodName: true,
}

// Test_Authz_CAMethods checks the role matrix of the dev configuration
// for every method of the CA and the Admin services, as the authorization
// interceptor of each listener evaluates it: on the backend the RA and the
// admin operate the CA, the CIS reaches its three methods, every other
// identity is refused, and a path without a rule is refused to everyone;
// the Admin API is for the admin and the peer. The wfe listener does not
// serve the CA, and its Admin rule admits the admin only. The wfe keeps
// the root path public for the UI, so a path without a rule is open there
// at this layer and relies on the access check of the method.
func Test_Authz_CAMethods(t *testing.T) {
	cfgPath, err := filepath.Abs(projFolder + "etc/dev/" + config.ConfigFileName)
	require.NoError(t, err)
	cfg := new(config.Configuration)
	require.NoError(t, config.LoadForHostName(cfgPath, "", cfg))
	backend := cfg.HTTPServers["backend"]
	require.NotNil(t, backend)
	wfe := cfg.HTTPServers["wfe"]
	require.NotNil(t, wfe)

	caMethods := serviceMethods(&pb.CA_ServiceDesc)
	adminMethods := serviceMethods(&privpb.Admin_ServiceDesc)
	require.NotEmpty(t, caMethods)
	require.NotEmpty(t, adminMethods)

	allowed := func(t *testing.T, cfg *authz.Config, role, method string) bool {
		t.Helper()
		prov, err := authz.New(cfg)
		require.NoError(t, err)
		prov.SetGRPCRoleMapper(func(context.Context) identity.Identity {
			return identity.NewIdentity(role, role, "", nil, "", "", identity.MethodCertificate)
		})
		called := false
		_, err = prov.NewUnaryInterceptor()(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: method},
			func(context.Context, any) (any, error) {
				called = true
				return nil, nil
			})
		return err == nil && called
	}

	for _, method := range caMethods {
		for _, role := range backendRoles {
			want := false
			switch role {
			case "trustyca-ra", "trustyca-admin":
				want = true
			case "trustyca-cis":
				want = cisMethods[method]
			}
			assert.Equal(t, want, allowed(t, backend.Authz, role, method), "backend %s for %s", method, role)
		}
	}
	for _, method := range adminMethods {
		for _, role := range backendRoles {
			want := role == "trustyca-admin" || role == "trustyca-peer"
			assert.Equal(t, want, allowed(t, backend.Authz, role, method), "backend %s for %s", method, role)
			assert.Equal(t, role == "trustyca-admin", allowed(t, wfe.Authz, role, method), "wfe %s for %s", method, role)
		}
	}
	// the backend denies by default: a service it does not serve, and the
	// routes of the wfe, have no rule
	for _, path := range []string{pb.Orgs_GetOrg_FullMethodName, pb.Auth_Caller_FullMethodName, pb.CIS_GetCertificateStatus_FullMethodName, pb.PathForAuthorize} {
		for _, role := range backendRoles {
			assert.False(t, allowed(t, backend.Authz, role, path), "backend %s for %s", path, role)
		}
	}
	for _, path := range []string{pb.PathForStatusVersion, pb.Status_Version_FullMethodName, "/healthz"} {
		assert.True(t, allowed(t, backend.Authz, identity.GuestRoleName, path), "backend %s", path)
	}
	// the CA is not served by the wfe listener, whose CIS is public
	assert.NotContains(t, wfe.Services, "ca")
	assert.NotContains(t, wfe.Services, "admin")
	assert.Contains(t, backend.Services, "ca")
	assert.True(t, allowed(t, wfe.Authz, identity.GuestRoleName, pb.CIS_GetCertificateStatus_FullMethodName))
}

// serviceMethods returns the full names of the methods of a gRPC service
func serviceMethods(desc *grpc.ServiceDesc) []string {
	res := make([]string, 0, len(desc.Methods))
	for _, m := range desc.Methods {
		res = append(res, "/"+desc.ServiceName+"/"+m.MethodName)
	}
	return res
}
