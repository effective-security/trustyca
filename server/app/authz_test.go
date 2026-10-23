package app

import (
	"context"
	"path/filepath"
	"slices"
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
var backendRoles = []string{"trustyca-ra", "trustyca-aia", "trustyca-admin", "trustyca-peer", "trustyca-client", identity.GuestRoleName}

// aiaMethods are the only methods of the backend the AIA identity may call:
// it forwards OCSP requests
var aiaMethods = map[string]bool{
	privpb.Backend_SignOCSP_FullMethodName: true,
}

// Test_Authz_CAMethods checks the role matrix of the dev configuration
// for every method of the CA, the backend and the Admin services, as the
// authorization interceptor of each listener evaluates it. On the backend
// the RA and the admin operate the CA, the WFE (the peer) reaches the
// backend service and the AIA its SignOCSP only, the Admin API is for the
// admin and the peer, every other identity is refused, and a path without
// a rule is refused to everyone. The wfe serves the CA and the CIS to any
// authenticated role and refuses a guest; it maps no TLS identity, serves
// neither the backend nor the Admin API, and its Admin rule admits the
// admin only. The wfe keeps the root path public for the UI, so a path
// without a rule is open there at this layer and relies on the access
// check of the method. The aia listener is public and denies by default:
// its routes and the status routes are open to a guest, everything else is
// refused.
func Test_Authz_CAMethods(t *testing.T) {
	cfgPath, err := filepath.Abs(projFolder + "etc/dev/" + config.ConfigFileName)
	require.NoError(t, err)
	cfg := new(config.Configuration)
	require.NoError(t, config.LoadForHostName(cfgPath, "", cfg))
	backend := cfg.HTTPServers[config.BackendServerName]
	require.NotNil(t, backend)
	wfe := cfg.HTTPServers[config.WFEServerName]
	require.NotNil(t, wfe)
	aia := cfg.HTTPServers[config.AIAServerName]
	require.NotNil(t, aia)

	caMethods := serviceMethods(&pb.CA_ServiceDesc)
	backendMethods := serviceMethods(&privpb.Backend_ServiceDesc)
	adminMethods := serviceMethods(&privpb.Admin_ServiceDesc)
	cisMethods := serviceMethods(&pb.CIS_ServiceDesc)
	require.NotEmpty(t, caMethods)
	require.NotEmpty(t, backendMethods)
	require.NotEmpty(t, adminMethods)
	require.NotEmpty(t, cisMethods)

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

	// the backend: service identities over mTLS
	assert.ElementsMatch(t, []string{"status", "admin", "backend", "ca"}, backend.Services)
	require.NotNil(t, backend.IdentityMap)
	assert.True(t, backend.IdentityMap.TLS.Enabled)
	for _, method := range caMethods {
		for _, role := range backendRoles {
			want := role == "trustyca-ra" || role == "trustyca-admin"
			assert.Equal(t, want, allowed(t, backend.Authz, role, method), "backend %s for %s", method, role)
		}
	}
	for _, method := range backendMethods {
		for _, role := range backendRoles {
			want := role == "trustyca-peer" || (role == "trustyca-aia" && aiaMethods[method])
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
	for _, path := range []string{pb.Orgs_GetOrg_FullMethodName, pb.Auth_Caller_FullMethodName, pb.CIS_GetCertificateStatus_FullMethodName, pb.PathForAuthorize, "/"} {
		for _, role := range backendRoles {
			assert.False(t, allowed(t, backend.Authz, role, path), "backend %s for %s", path, role)
		}
	}
	for _, path := range []string{pb.PathForStatusVersion, pb.Status_Version_FullMethodName, "/healthz"} {
		assert.True(t, allowed(t, backend.Authz, identity.GuestRoleName, path), "backend %s", path)
	}

	// the wfe: users and API keys; no service role is mapped there, and it
	// serves the CA, whose key operations run in the backend, and the CIS to
	// authenticated callers of any role
	require.NotNil(t, wfe.IdentityMap)
	assert.False(t, wfe.IdentityMap.TLS.Enabled, "the wfe maps no TLS identity")
	assert.Empty(t, wfe.IdentityMap.TLS.Roles)
	require.NotNil(t, wfe.ServerTLS)
	assert.False(t, wfe.ServerTLS.GetClientCertAuth(), "browsers connect without a client certificate")
	assert.Contains(t, wfe.Services, "ca")
	assert.Contains(t, wfe.Services, "cis")
	assert.NotContains(t, wfe.Services, "backend")
	assert.NotContains(t, wfe.Services, "admin")
	assert.NotContains(t, wfe.Services, "aia")
	for _, method := range append(slices.Clone(cisMethods), caMethods...) {
		assert.False(t, allowed(t, wfe.Authz, identity.GuestRoleName, method), "wfe %s for a guest", method)
		assert.True(t, allowed(t, wfe.Authz, "user", method), "wfe %s for a user", method)
		assert.True(t, allowed(t, wfe.Authz, "trustyca-admin", method), "wfe %s for the admin", method)
		assert.NotContains(t, wfe.IdentityMap.SkipAuthPaths, method, "the CIS and CA methods are authenticated")
	}

	// the aia listener is public and plain HTTP: no identity mapping, the
	// AIA and status routes open to a guest, every other path refused
	assert.Nil(t, aia.IdentityMap)
	assert.Nil(t, aia.ServerTLS)
	assert.Equal(t, []string{"status", "aia"}, aia.Services)
	for _, path := range []string{
		pb.PathForOCSP,
		"/v1/ocsp/MEowSDBGMEQwQjAJBgUrDgMCGgUA",
		"/v1/ocspi/0a1b2c",
		"/v1/ocspi/0a1b2c/MEowSDBGMEQwQjAJBgUrDgMCGgUA",
		"/v1/cert/0a1b2c",
		"/v1/crl/0a1b2c",
		pb.PathForStatusNode,
		pb.PathForStatusVersion,
		pb.Status_Version_FullMethodName,
		"/healthz",
	} {
		assert.True(t, allowed(t, aia.Authz, identity.GuestRoleName, path), "aia %s", path)
	}
	for _, path := range []string{"/", "/v1", "/v1/auth/providers", pb.PathForAuthorize, pb.Orgs_GetOrg_FullMethodName, pb.CA_SignOCSP_FullMethodName, privpb.Backend_SignOCSP_FullMethodName, privpb.Admin_ListOrgs_FullMethodName} {
		for _, role := range backendRoles {
			assert.False(t, allowed(t, aia.Authz, role, path), "aia %s for %s", path, role)
		}
	}
	for _, path := range cisMethods {
		assert.False(t, allowed(t, aia.Authz, "user", path), "aia %s: the JSON API is the wfe's", path)
	}
}

// serviceMethods returns the full names of the methods of a gRPC service
func serviceMethods(desc *grpc.ServiceDesc) []string {
	res := make([]string, 0, len(desc.Methods))
	for _, m := range desc.Methods {
		res = append(res, "/"+desc.ServiceName+"/"+m.MethodName)
	}
	return res
}
