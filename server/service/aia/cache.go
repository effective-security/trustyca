package aia

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/cockroachdb/errors"
	lru "github.com/hashicorp/golang-lru/v2"
)

// ocspKey identifies an OCSP request by the SHA-256 of its DER encoding, so
// that a request with a nonce is never answered from the cache of another
type ocspKey [sha256.Size]byte

// ocspEntry is a signed OCSP response the CA produced, kept until its
// NextUpdate
type ocspEntry struct {
	der        []byte
	thisUpdate time.Time
	nextUpdate time.Time
	// etag is the quoted SHA-256 of the response
	etag string
}

// ocspCache keeps the most recently used OCSP responses in memory, keyed by
// the hash of the request
type ocspCache struct {
	entries *lru.Cache[ocspKey, *ocspEntry]
}

// newOcspCache returns a cache of at most size responses
func newOcspCache(size int) (*ocspCache, error) {
	entries, err := lru.New[ocspKey, *ocspEntry](size)
	if err != nil {
		return nil, errors.WithMessage(err, "unable to create the OCSP cache")
	}
	return &ocspCache{entries: entries}, nil
}

// keyOf returns the cache key of a DER request
func keyOf(der []byte) ocspKey {
	return sha256.Sum256(der)
}

// get returns the cached response of the request when it is still valid at
// the time; an expired response is removed
func (c *ocspCache) get(key ocspKey, now time.Time) (*ocspEntry, bool) {
	e, ok := c.entries.Get(key)
	if !ok {
		return nil, false
	}
	if !now.Before(e.nextUpdate) {
		c.entries.Remove(key)
		return nil, false
	}
	return e, true
}

// add stores the response of the request
func (c *ocspCache) add(key ocspKey, e *ocspEntry) {
	c.entries.Add(key, e)
}

// len returns the number of cached responses, expired ones included
func (c *ocspCache) len() int {
	return c.entries.Len()
}

// etagOf returns the quoted SHA-256 of a body, the ETag of a response
func etagOf(body []byte) string {
	sum := sha256.Sum256(body)
	return `"` + hex.EncodeToString(sum[:]) + `"`
}
