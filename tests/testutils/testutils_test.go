package testutils_test

import (
	"net"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/effective-security/trustyca/tests/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test_PortAllocation_concurrent races every port helper from many
// goroutines: the reservation set must be guarded, and no port may be
// handed out twice in the process.
func Test_PortAllocation_concurrent(t *testing.T) {
	t.Parallel()

	const (
		workers  = 16
		perBatch = 3
	)

	var (
		mu    sync.Mutex
		ports = map[string]string{}
		wg    sync.WaitGroup
	)
	// the workers report with assert: FailNow must not run off the test
	// goroutine
	record := func(t *testing.T, owner, hostport string) {
		_, port, err := net.SplitHostPort(hostport)
		if !assert.NoError(t, err, hostport) {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		prev, dup := ports[port]
		assert.False(t, dup, "port %s handed to %s and %s", port, prev, owner)
		ports[port] = owner
	}
	hostOf := func(t *testing.T, rawURL string) string {
		u, err := url.Parse(rawURL)
		if !assert.NoError(t, err, rawURL) {
			return ""
		}
		return u.Host
	}

	for range workers {
		wg.Go(func() {
			u := testutils.CreateURL("http", "localhost")
			assert.True(t, strings.HasPrefix(u, "http://localhost:"), u)
			record(t, "CreateURL", hostOf(t, u))

			record(t, "CreateBindAddr", testutils.CreateBindAddr("localhost"))

			list := testutils.CreateURLs("https", "localhost", perBatch)
			assert.Len(t, list, perBatch)
			for _, u := range list {
				assert.True(t, strings.HasPrefix(u, "https://localhost:"), u)
				record(t, "CreateURLs", hostOf(t, u))
			}
		})
	}
	wg.Wait()
	assert.Len(t, ports, workers*(2+perBatch))
}

func Test_CreateBindAddr_emptyHost(t *testing.T) {
	t.Parallel()
	// an empty host binds every interface, as the servers' listen URLs do
	addr := testutils.CreateBindAddr("")
	host, port, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	assert.Empty(t, host)
	assert.NotEmpty(t, port)

	assert.Empty(t, testutils.CreateURLs("http", "localhost", 0))
}
