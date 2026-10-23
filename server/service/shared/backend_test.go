package shared_test

import (
	"context"
	"sync"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/pkg/discovery"
	"github.com/effective-security/trustyca/api/client"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/mocks/mockclient"
	"github.com/effective-security/trustyca/privpb"
	"github.com/effective-security/trustyca/server/service/shared"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// backendName is the listener the tests dial
const backendName = "backend"

// forwarder takes the public requests, as the CA service that forwards to
// the backend does: it is not a privpb.BackendServer
type forwarder struct {
	pb.UnimplementedCAServer
}

// localBackend is the backend service of the process: it answers OCSP
type localBackend struct {
	privpb.UnimplementedBackendServer
}

func (b *localBackend) SignOCSP(context.Context, *pb.OCSPRequest) (*pb.OCSPResponse, error) {
	return &pb.OCSPResponse{Der: []byte("local")}, nil
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
// finds it by privpb.BackendServer, never the forwarding CA service
// registered beside it, and it is called directly; the factory is not used
func TestBackendLocator_Local(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	factory := mockclient.NewMockFactory(ctrl)

	disco := discovery.New()
	require.NoError(t, disco.Register("wfe", &forwarder{}))
	local := &localBackend{}
	require.NoError(t, disco.Register(backendName, local))
	l := shared.NewBackendLocator(func() discovery.Discovery { return disco }, factory, client.ClientNameCA, backendName)

	srv, err := l.Backend()
	require.NoError(t, err)
	assert.Same(t, local, srv)
	res, err := srv.SignOCSP(context.Background(), &pb.OCSPRequest{})
	require.NoError(t, err)
	assert.Equal(t, []byte("local"), res.Der)
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
// factory that fails is tried again on the next call, and the client is
// kept until Close, which closes it
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
// backend is returned as is, also after Close
func TestBackendLocator_Static(t *testing.T) {
	t.Parallel()
	local := &localBackend{}
	l := shared.NewStaticBackendLocator(local)
	srv, err := l.Backend()
	require.NoError(t, err)
	assert.Same(t, local, srv)
	assert.NoError(t, l.Close())
	srv, err = l.Backend()
	require.NoError(t, err)
	assert.Same(t, local, srv, "a static backend is kept after Close")
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
		})
	}
	wg.Wait()
	require.NoError(t, l.Close())
}
