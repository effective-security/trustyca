package service

import (
	"net/http"
	"net/url"

	"github.com/effective-security/porto/gserver"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/trustyca/server/service/admin"
	"github.com/effective-security/trustyca/server/service/auth"
	"github.com/effective-security/trustyca/server/service/ca"
	"github.com/effective-security/trustyca/server/service/orgs"
	"github.com/effective-security/trustyca/server/service/status"
	"github.com/effective-security/trustyca/server/service/ui"
)

// Factories provides map of gserver.ServiceFactory
var Factories = map[string]gserver.ServiceFactory{
	admin.ServiceName:  admin.Factory,
	auth.ServiceName:   auth.Factory,
	ca.ServiceName:     ca.Factory,
	orgs.ServiceName:   orgs.Factory,
	status.ServiceName: status.Factory,
	ui.ServiceName:     ui.Factory,
}

// GetPublicServerURL returns complete server URL for given relative end-point
func GetPublicServerURL(r *http.Request, relativeEndpoint string) *url.URL {
	proto := r.URL.Scheme

	// Allow upstream proxies  to specify the forwarded protocol. Allow this value
	// to override our own guess.
	if specifiedProto := r.Header.Get(header.XForwardedProto); specifiedProto != "" {
		proto = specifiedProto
	}

	host := r.URL.Host
	if host == "" {
		host = r.Host
	}
	if proto == "" {
		proto = "https"
	}

	return &url.URL{
		Scheme: proto,
		Host:   host,
		Path:   relativeEndpoint,
	}
}
