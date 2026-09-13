package authctx

import "strings"

// Token claims used by API keys and scoped access tokens
const (
	// ClaimScope lists the scopes granted to an API key or a scoped token.
	// A method with (es.api.scopes) requires every listed scope to be
	// granted. "*" grants everything; "certs:*" grants every certs scope.
	ClaimScope = "scope"
	// ClaimProject is the project an API key is restricted to, if any
	ClaimProject = "project"
)

// Scopes are the API scopes (permissions) that can be granted to API keys.
// A method declares the scopes it requires with (es.api.scopes).
const (
	ScopeOrgRead      = "org:read"
	ScopeProjectRead  = "project:read"
	ScopeCARead       = "ca:read"
	ScopeCAWrite      = "ca:write"
	ScopeCertsRead    = "certs:read"
	ScopeCertsIssue   = "certs:issue"
	ScopeCertsRevoke  = "certs:revoke"
	ScopeAll          = "*"
	scopeWildcardMark = "*"
)

// DefaultAPIKeyScopes are granted to an API key created without scopes
var DefaultAPIKeyScopes = []string{ScopeOrgRead, ScopeProjectRead, ScopeCARead}

// KnownScopes lists the scopes an API key may be created with
var KnownScopes = []string{
	ScopeOrgRead, ScopeProjectRead, ScopeCARead, ScopeCAWrite,
	ScopeCertsRead, ScopeCertsIssue, ScopeCertsRevoke,
}

// ParseScopes splits the (es.api.scopes) option values, which may be comma
// separated, into scope names
func ParseScopes(values []string) []string {
	var res []string
	for _, v := range values {
		for _, s := range strings.Split(v, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				res = append(res, s)
			}
		}
	}
	return res
}

// HasScope returns true if the granted scopes cover the scope, exactly,
// through "*", or through a prefix wildcard such as "certs:*"
func HasScope(granted []string, scope string) bool {
	for _, g := range granted {
		g = strings.TrimSpace(g)
		switch {
		case g == scope || g == ScopeAll:
			return true
		case strings.HasSuffix(g, scopeWildcardMark) && strings.HasPrefix(scope, g[:len(g)-1]):
			return true
		}
	}
	return false
}

// HasScopes returns true if the granted scopes cover every required scope.
// A method without required scopes is covered by any grant.
func HasScopes(granted []string, required []string) bool {
	for _, r := range required {
		if !HasScope(granted, r) {
			return false
		}
	}
	return true
}

// IsKnownScope returns true if the scope may be granted to an API key
func IsKnownScope(scope string) bool {
	if scope == ScopeAll {
		return true
	}
	for _, k := range KnownScopes {
		if k == scope {
			return true
		}
		// prefix wildcard of a known family, e.g. certs:*
		if strings.HasSuffix(scope, scopeWildcardMark) && strings.HasPrefix(k, scope[:len(scope)-1]) {
			return true
		}
	}
	return false
}
