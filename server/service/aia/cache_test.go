package aia

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOcspCache(t *testing.T) {
	t.Parallel()
	_, err := newOcspCache(0)
	assert.EqualError(t, err, "unable to create the OCSP cache: must provide a positive size")
	c, err := newOcspCache(2)
	require.NoError(t, err)

	now := time.Now()
	req := []byte("request-1")
	key := keyOf(req)
	assert.Equal(t, sha256.Sum256(req), [32]byte(key))
	_, ok := c.get(key, now)
	assert.False(t, ok)

	e := &ocspEntry{
		der:        []byte("response-1"),
		thisUpdate: now.Add(-time.Minute),
		nextUpdate: now.Add(time.Hour),
		etag:       etagOf([]byte("response-1")),
	}
	c.add(key, e)
	got, ok := c.get(key, now)
	require.True(t, ok)
	assert.Same(t, e, got)
	assert.Equal(t, 1, c.len())

	// the entry is served until its next update, and removed once it is
	// past it
	_, ok = c.get(key, e.nextUpdate.Add(-time.Second))
	assert.True(t, ok)
	_, ok = c.get(key, e.nextUpdate)
	assert.False(t, ok, "at NextUpdate")
	assert.Equal(t, 0, c.len(), "removed")
	_, ok = c.get(key, now)
	assert.False(t, ok)

	// the least recently used entry is evicted at the size
	c.add(keyOf([]byte("a")), e)
	c.add(keyOf([]byte("b")), e)
	_, ok = c.get(keyOf([]byte("a")), now)
	assert.True(t, ok)
	c.add(keyOf([]byte("c")), e)
	assert.Equal(t, 2, c.len())
	_, ok = c.get(keyOf([]byte("b")), now)
	assert.False(t, ok, "the least recently used")
	_, ok = c.get(keyOf([]byte("a")), now)
	assert.True(t, ok)
	_, ok = c.get(keyOf([]byte("c")), now)
	assert.True(t, ok)

	// the ETag is the quoted hash of the body
	sum := sha256.Sum256([]byte("response-1"))
	assert.Equal(t, `"`+hex.EncodeToString(sum[:])+`"`, e.etag)
}

// TestOcspCache_Concurrent reads and writes the cache from many goroutines
// under the race detector
func TestOcspCache_Concurrent(t *testing.T) {
	t.Parallel()
	c, err := newOcspCache(16)
	require.NoError(t, err)
	now := time.Now()
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range 100 {
				key := keyOf(fmt.Appendf(nil, "%d-%d", i, j%20))
				if _, ok := c.get(key, now); !ok {
					c.add(key, &ocspEntry{nextUpdate: now.Add(time.Hour)})
				}
			}
		}()
	}
	wg.Wait()
	assert.LessOrEqual(t, c.len(), 16)
}
