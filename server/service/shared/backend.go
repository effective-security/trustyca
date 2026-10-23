package shared

import (
	"io"
	"sync"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/pkg/discovery"
	"github.com/effective-security/trustyca/api/client"
	"github.com/effective-security/trustyca/privpb"
)

// BackendLocator returns the backend the CA service forwards every call
// to, and the AIA its OCSP requests (DESIGN.md section 2.1): the backend
// service of the same process when discovery has one, else a client of the
// backend listener dialed with the named service client. The lookup runs on the
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
// a service wired to its backend explicitly
func NewStaticBackendLocator(srv privpb.BackendServer) *BackendLocator {
	return &BackendLocator{
		srv: srv,
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

// findLocal returns the backend service of the process, or nil. Only the
// backend service implements privpb.BackendServer: the CA service that
// forwards to it takes the public requests.
func (l *BackendLocator) findLocal() privpb.BackendServer {
	if l.disco == nil {
		return nil
	}
	disco := l.disco()
	if disco == nil {
		return nil
	}
	var local privpb.BackendServer
	if err := disco.Find("", &local); err != nil {
		return nil
	}
	return local
}
