package shared_test

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/pkg/discovery"
	"github.com/effective-security/trustyca/api/client"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/mocks/mockclient"
	"github.com/effective-security/trustyca/privpb"
	"github.com/effective-security/trustyca/server/service/shared"
	"github.com/effective-security/xdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// backendName is the listener the tests dial
const backendName = "backend"

// forwarder has the methods of privpb.BackendServer, as the CA service that
// forwards to the backend has them, but is not a LocalBackend
type forwarder struct {
	privpb.UnimplementedBackendServer
}

// localBackend is the backend service of the process: it answers OCSP and
// records the profiles it invalidates
type localBackend struct {
	privpb.UnimplementedBackendServer
	mu          sync.Mutex
	invalidated []string
}

func (b *localBackend) SignOCSP(context.Context, *pb.OCSPRequest) (*pb.OCSPResponse, error) {
	return &pb.OCSPResponse{Der: []byte("local")}, nil
}

func (b *localBackend) InvalidateProfile(orgID, projectID xdb.ID, label string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.invalidated = append(b.invalidated, fmt.Sprintf("%d/%d/%s", orgID.UInt64(), projectID.UInt64(), label))
}

func (b *localBackend) profiles() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.invalidated...)
}

// closeCounter counts its closes
type closeCounter struct {
	closed int
}

func (c *closeCounter) Close() error {
	c.closed++
	return nil
}

// TestBackendLocator_Local covers the backend of the process: discovery
// finds it by client.LocalBackend, never the forwarding service registered
// beside it, it is called directly and invalidates the profiles; the
// factory is not used
func TestBackendLocator_Local(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	factory := mockclient.NewMockFactory(ctrl)

	disco := discovery.New()
	require.NoError(t, disco.Register("wfe", &forwarder{}))
	local := &localBackend{}
	require.NoError(t, disco.Register(backendName, local))
	l := shared.NewBackendLocator(func() discovery.Discovery { return disco }, factory, client.ClientNameCA, backendName)

	// a profile is invalidated before the first call too
	l.InvalidateProfile(xdb.NewID(1), xdb.NewID(0), "server")
	assert.Equal(t, []string{"1/0/server"}, local.profiles())

	srv, err := l.Backend()
	require.NoError(t, err)
	assert.Same(t, local, srv)
	res, err := srv.SignOCSP(context.Background(), &pb.OCSPRequest{})
	require.NoError(t, err)
	assert.Equal(t, []byte("local"), res.Der)
	l.InvalidateProfile(xdb.NewID(1), xdb.NewID(201), "peer")
	assert.Equal(t, []string{"1/0/server", "1/201/peer"}, local.profiles())
	assert.NoError(t, l.Close())

	// the forwarding service alone is not a backend: with no factory there
	// is none
	disco = discovery.New()
	require.NoError(t, disco.Register("wfe", &forwarder{}))
	l = shared.NewBackendLocator(func() discovery.Discovery { return disco }, nil, client.ClientNameCA, backendName)
	_, err = l.Backend()
	assert.EqualError(t, err, "backend is not configured")

	// no discovery yet, as before the server started
	l = shared.NewBackendLocator(func() discovery.Discovery { return nil }, nil, client.ClientNameCA, backendName)
	_, err = l.Backend()
	assert.EqualError(t, err, "backend is not configured")
}

// TestBackendLocator_Remote covers the client of the backend listener: a
// factory that fails is tried again on the next call, the client is kept
// until Close, which closes it, and a profile change is not sent to a
// remote backend
func TestBackendLocator_Remote(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	factory := mockclient.NewMockFactory(ctrl)
	remote := &localBackend{}
	closer := &closeCounter{}
	gomock.InOrder(
		factory.EXPECT().BackendClient(client.ClientNameAIA, backendName).Return(nil, nil, errors.New("backend down")),
		factory.EXPECT().BackendClient(client.ClientNameAIA, backendName).Return(remote, closer, nil),
		factory.EXPECT().BackendClient(client.ClientNameAIA, backendName).Return(remote, closer, nil),
	)
	l := shared.NewBackendLocator(nil, factory, client.ClientNameAIA, backendName)

	_, err := l.Backend()
	assert.EqualError(t, err, "unable to create the backend client: backend down")
	for range 2 {
		srv, err := l.Backend()
		require.NoError(t, err)
		assert.Same(t, remote, srv)
	}
	l.InvalidateProfile(xdb.NewID(1), xdb.NewID(0), "server")
	assert.Empty(t, remote.profiles(), "a remote backend learns of the change after its cache TTL")

	require.NoError(t, l.Close())
	assert.Equal(t, 1, closer.closed)
	require.NoError(t, l.Close(), "a second close has nothing to close")
	assert.Equal(t, 1, closer.closed)

	// the next call dials again
	srv, err := l.Backend()
	require.NoError(t, err)
	assert.Same(t, remote, srv)
	require.NoError(t, l.Close())
	assert.Equal(t, 2, closer.closed)
}

// TestBackendLocator_Static covers a locator wired to its backend: the
// backend is returned as is, and profiles are invalidated in a local one
func TestBackendLocator_Static(t *testing.T) {
	t.Parallel()
	local := &localBackend{}
	l := shared.NewStaticBackendLocator(local)
	srv, err := l.Backend()
	require.NoError(t, err)
	assert.Same(t, local, srv)
	l.InvalidateProfile(xdb.NewID(2), xdb.NewID(0), "server")
	assert.Equal(t, []string{"2/0/server"}, local.profiles())
	assert.NoError(t, l.Close())
	srv, err = l.Backend()
	require.NoError(t, err)
	assert.Same(t, local, srv, "a static backend is kept after Close")

	fwd := &forwarder{}
	l = shared.NewStaticBackendLocator(fwd)
	srv, err = l.Backend()
	require.NoError(t, err)
	assert.Same(t, fwd, srv)
	l.InvalidateProfile(xdb.NewID(2), xdb.NewID(0), "server")
}

// TestBackendLocator_Concurrent looks the backend up from many goroutines
// at once: the factory dials once
func TestBackendLocator_Concurrent(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	factory := mockclient.NewMockFactory(ctrl)
	remote := &localBackend{}
	factory.EXPECT().BackendClient(client.ClientNameCA, backendName).Return(remote, &closeCounter{}, nil).Times(1)
	l := shared.NewBackendLocator(nil, factory, client.ClientNameCA, backendName)

	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			srv, err := l.Backend()
			assert.NoError(t, err)
			assert.Same(t, remote, srv)
			l.InvalidateProfile(xdb.NewID(1), xdb.NewID(0), "server")
		})
	}
	wg.Wait()
	require.NoError(t, l.Close())
}
