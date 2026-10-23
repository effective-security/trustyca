package shared

import (
	"io"
	"sync"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/pkg/discovery"
	"github.com/effective-security/trustyca/api/client"
	"github.com/effective-security/trustyca/privpb"
	"github.com/effective-security/xdb"
)

// LocalBackend is the backend service (privpb.Backend) as porto discovery
// finds it in the process that runs it. The CA service that forwards to the
// backend has the methods of privpb.BackendServer too, so discovery looks
// the backend up by this interface, which the forwarding service does not
// implement.
type LocalBackend interface {
	privpb.BackendServer

	// InvalidateProfile drops the cached resolutions of the profile label
	// in the scope, after the profile changed
	InvalidateProfile(orgID, projectID xdb.ID, label string)
}

// BackendLocator returns the backend a service forwards the key operations
// or the OCSP requests to (DESIGN.md section 2.1): the backend service of
// the same process when discovery has one, else a client of the backend
// listener dialed with the named service client. The lookup runs on the
// first call, never at startup, because the gRPC client blocks until the
// backend is reachable and the listeners start in any order; a failure is
// returned and the next call tries again. The backend found is kept until
// Close. A BackendLocator is safe for concurrent use.
type BackendLocator struct {
	disco      func() discovery.Discovery
	clients    client.Factory
	clientName string
	server     string

	lock   sync.Mutex
	srv    privpb.BackendServer
	local  LocalBackend
	closer io.Closer
}

// NewBackendLocator returns the locator of the backend: disco returns the
// discovery of the process, or nil; clients dials the listener named server
// with the client named clientName when the process has no backend. Either
// may be nil.
func NewBackendLocator(disco func() discovery.Discovery, clients client.Factory, clientName, server string) *BackendLocator {
	return &BackendLocator{
		disco:      disco,
		clients:    clients,
		clientName: clientName,
		server:     server,
	}
}

// NewStaticBackendLocator returns a locator that always returns srv, for
// a service wired to its backend explicitly; profiles are invalidated in
// srv when it is a LocalBackend
func NewStaticBackendLocator(srv privpb.BackendServer) *BackendLocator {
	local, _ := srv.(LocalBackend)
	return &BackendLocator{
		srv:   srv,
		local: local,
	}
}

// Backend returns the backend: the one of the process, called directly with
// the context of the caller, or a client of the backend listener
func (l *BackendLocator) Backend() (privpb.BackendServer, error) {
	l.lock.Lock()
	defer l.lock.Unlock()
	if l.srv != nil {
		return l.srv, nil
	}

	if local := l.findLocal(); local != nil {
		l.local = local
		l.srv = local
		return l.srv, nil
	}

	if l.clients == nil {
		return nil, errors.New("backend is not configured")
	}
	srv, closer, err := l.clients.BackendClient(l.clientName, l.server)
	if err != nil {
		return nil, errors.WithMessage(err, "unable to create the backend client")
	}
	l.srv = srv
	l.closer = closer
	return srv, nil
}

// InvalidateProfile invalidates the profile in the backend of the process,
// when the process runs one; a remote backend learns of the change after
// the TTL of its cache
func (l *BackendLocator) InvalidateProfile(orgID, projectID xdb.ID, label string) {
	l.lock.Lock()
	local := l.local
	if local == nil && l.srv == nil {
		local = l.findLocal()
	}
	l.lock.Unlock()
	if local != nil {
		local.InvalidateProfile(orgID, projectID, label)
	}
}

// Close closes the client of a remote backend; the next call of Backend
// looks the backend up again
func (l *BackendLocator) Close() error {
	l.lock.Lock()
	defer l.lock.Unlock()
	if l.closer == nil {
		return nil
	}
	err := l.closer.Close()
	l.closer = nil
	l.srv = nil
	return err
}

// findLocal returns the backend service of the process, or nil
func (l *BackendLocator) findLocal() LocalBackend {
	if l.disco == nil {
		return nil
	}
	disco := l.disco()
	if disco == nil {
		return nil
	}
	var local LocalBackend
	if err := disco.Find("", &local); err != nil {
		return nil
	}
	return local
}
