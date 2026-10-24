package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"testing"

	"github.com/cockroachdb/errors"
	tcredentials "github.com/effective-security/porto/gserver/credentials"
	"github.com/effective-security/porto/gserver/roles"
	"github.com/effective-security/porto/restserver/authz"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/identity"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/authctx"
	"github.com/effective-security/trustyca/internal/config"
	"github.com/effective-security/trustyca/privpb"
	"github.com/effective-security/xpki/jwt"
	"github.com/effective-security/xpki/jwt/dpop"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

// The roles the backend listener maps (identity_map of
// etc/dev/trustyca-config.yaml): the service identities of client
// certificates, the operator of a DPoP token, and the default role of any
// other certificate or token
var backendRoles = []string{"trustyca-ra", "trustyca-aia", "trustyca-admin", "trustyca-peer", "trustyca-client", "user", identity.GuestRoleName}

// operatorRole is the role of the operators, a DPoP token on the wfe and on
// the backend
const operatorRole = "trustyca-admin"

// aiaMethods are the only methods of the backend the AIA identity may call:
// it forwards OCSP requests
var aiaMethods = map[string]bool{
	privpb.Backend_SignOCSP_FullMethodName: true,
}

// Test_Authz_CAMethods checks the role matrix of the dev configuration
// for every method of the CA, the backend and the Admin services, as the
// authorization interceptor of each listener evaluates it. On the backend
// the WFE (the peer), the RA and the admin reach every method of the
// backend service and the AIA its SignOCSP only, the Admin API is for the
// admin and the peer, every other identity is refused, the public CA is not
// served, and a path without a rule is refused to everyone. The wfe serves
// the CA and the CIS to any
// authenticated role and refuses a guest; it maps no TLS identity, serves
// neither the backend nor the Admin API, and its Admin rule admits the
// admin only. The wfe keeps the root path public for the UI, so a path
// without a rule is open there at this layer and relies on the access
// check of the method. The aia listener is public and denies by default:
// its routes and the status routes are open to a guest, everything else is
// refused.
func Test_Authz_CAMethods(t *testing.T) {
	cfg := devConfig(t)
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

	allowed := allowedFor

	// the backend: service identities over mTLS, the operator by DPoP
	// (Test_Identity_Backend)
	assert.ElementsMatch(t, []string{"status", "admin", "backend"}, backend.Services)
	require.NotNil(t, backend.IdentityMap)
	assert.True(t, backend.IdentityMap.TLS.Enabled)
	// the public CA takes the org of a token, which a service identity has
	// not: the backend does not serve it, and has no rule for it
	for _, method := range caMethods {
		for _, role := range backendRoles {
			assert.False(t, allowed(t, backend.Authz, role, method), "backend %s for %s", method, role)
		}
	}
	for _, method := range backendMethods {
		for _, role := range backendRoles {
			want := role == "trustyca-peer" || role == "trustyca-ra" || role == "trustyca-admin" ||
				(role == "trustyca-aia" && aiaMethods[method])
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
	// serves the CA, which forwards every call to the backend, and the CIS to
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

// Test_Identity_Backend checks the identity map of the backend listener of
// the dev configuration with the identity provider porto builds from it:
// the operator is a DPoP token of the wfe whose email the map lists as
// trustyca-admin, and no client certificate is, the certificate the operator
// was once given included; another DPoP token and another certificate are
// the default role, which the authz rules refuse, a bearer token is a
// guest, and a service certificate is its service role.
func Test_Identity_Backend(t *testing.T) {
	cfg := devConfig(t)
	backend := cfg.HTTPServers[config.BackendServerName]
	require.NotNil(t, backend)
	wfe := cfg.HTTPServers[config.WFEServerName]
	require.NotNil(t, wfe)
	idm := backend.IdentityMap
	require.NotNil(t, idm)
	require.NotNil(t, wfe.IdentityMap)

	assert.True(t, idm.DPoP.Enabled)
	assert.False(t, idm.JWT.Enabled, "bearer tokens are not mapped")
	assert.Equal(t, wfe.IdentityMap.DPoP, idm.DPoP, "the tokens and the operators of the wfe")
	assert.Len(t, idm.DPoP.Roles, 1, "the operators are the only role of a token")
	admins := idm.DPoP.Roles[operatorRole]
	require.NotEmpty(t, admins)
	assert.NotContains(t, idm.TLS.Roles, operatorRole, "no client certificate is the operator")

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signer, err := dpop.NewSigner(key)
	require.NoError(t, err)
	claims := func(email string) jwt.MapClaims {
		return jwt.MapClaims{
			"iss":   idm.DPoP.Issuer,
			"aud":   idm.DPoP.Audience,
			"sub":   "7",
			"email": email,
			"org":   "42",
			"cnf":   map[string]any{"jkt": signer.JWKThumbprint()},
		}
	}
	prov, err := roles.New(idm, tokenParser{
		"operator": claims(admins[0]),
		"user":     claims("user1@trustyca.io"),
	})
	require.NoError(t, err)

	method := privpb.Backend_ListRoots_FullMethodName
	call := func(t *testing.T, authorization string) identity.Identity {
		t.Helper()
		proof, err := signer.Sign(context.Background(), http.MethodPost, &url.URL{Scheme: "https", Host: "localhost:8881", Path: method}, nil)
		require.NoError(t, err)
		md := metadata.Pairs(
			tcredentials.TokenFieldNameGRPC, authorization,
			header.DPoP, proof,
			header.Authority, "localhost:8881",
		)
		id, err := prov.IdentityFromContext(metadata.NewIncomingContext(context.Background(), md), method)
		require.NoError(t, err)
		return id
	}
	operator := call(t, header.DPoP+" operator")
	assert.Equal(t, operatorRole, operator.Role())
	assert.Equal(t, "42", operator.Tenant(), "the org of the login, which is not the scope of the operator")
	assert.True(t, allowedFor(t, backend.Authz, operator.Role(), method))
	user := call(t, header.DPoP+" user")
	assert.Equal(t, idm.DPoP.DefaultAuthenticatedRole, user.Role())
	assert.False(t, allowedFor(t, backend.Authz, user.Role(), method))
	assert.Equal(t, identity.GuestRoleName, call(t, "Bearer operator").Role())

	certificate := func(t *testing.T, spiffe string) identity.Identity {
		t.Helper()
		u, err := url.Parse(spiffe)
		require.NoError(t, err)
		crt := &x509.Certificate{URIs: []*url.URL{u}, Subject: pkix.Name{CommonName: "test"}}
		ctx := peer.NewContext(context.Background(), &peer.Peer{
			AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{crt}}},
		})
		id, err := prov.IdentityFromContext(ctx, method)
		require.NoError(t, err)
		return id
	}
	admin := certificate(t, "spiffe://trustyca/admin")
	assert.Equal(t, idm.TLS.DefaultAuthenticatedRole, admin.Role())
	assert.False(t, allowedFor(t, backend.Authz, admin.Role(), method))
	assert.Equal(t, "trustyca-ra", certificate(t, "spiffe://trustyca/ra").Role())
	assert.Equal(t, authctx.PeerRoleName, certificate(t, "spiffe://trustyca/peer").Role())
}

// tokenParser returns the claims of a token by its value, as a jwt.Parser
// does for a token it verified; it checks the issuer and audience the
// listener expects
type tokenParser map[string]jwt.MapClaims

// ParseToken returns the claims of the token
func (p tokenParser) ParseToken(_ context.Context, token string, cfg *jwt.VerifyConfig) (jwt.MapClaims, error) {
	claims, ok := p[token]
	if !ok {
		return nil, errors.New("invalid token")
	}
	if cfg.ExpectedIssuer != claims.String("iss") || !slices.Contains(cfg.ExpectedAudience, claims.String("aud")) {
		return nil, errors.New("invalid issuer or audience")
	}
	return claims, nil
}

// GetRevocation returns no revocation checker
func (tokenParser) GetRevocation() jwt.Revocation { return nil }

// SetRevocation ignores the checker
func (tokenParser) SetRevocation(jwt.Revocation) {}

// devConfig loads etc/dev/trustyca-config.yaml
func devConfig(t *testing.T) *config.Configuration {
	t.Helper()
	cfgPath, err := filepath.Abs(projFolder + "etc/dev/" + config.ConfigFileName)
	require.NoError(t, err)
	cfg := new(config.Configuration)
	require.NoError(t, config.LoadForHostName(cfgPath, "", cfg))
	return cfg
}

// allowedFor returns true when the authz interceptor of the listener admits
// the role to the method
func allowedFor(t *testing.T, cfg *authz.Config, role, method string) bool {
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

// serviceMethods returns the full names of the methods of a gRPC service
func serviceMethods(desc *grpc.ServiceDesc) []string {
	res := make([]string, 0, len(desc.Methods))
	for _, m := range desc.Methods {
		res = append(res, "/"+desc.ServiceName+"/"+m.MethodName)
	}
	return res
}
