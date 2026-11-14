package daneauth

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/shuque/dane/v2"
)

const (
	defaultCacheEntries = 10000
	defaultNegTTL       = 30 * time.Second
	maxCacheTTL         = 3600 * time.Second
)

// lookupFunc fetches the TLSA RRset at qname (dane.Resolver.LookupTLSA).
type lookupFunc func(ctx context.Context, qname string) (*dane.RRset, error)

type cacheEntry struct {
	rrset   *dane.RRset
	err     error
	expires time.Time
}

// tlsaCache caches TLSA lookups for their TTL. Concurrent lookups of the
// same uncached name may each query; there is no singleflight.
type tlsaCache struct {
	lookup     lookupFunc
	maxEntries int
	now        func() time.Time

	mu      sync.Mutex
	entries map[string]cacheEntry
}

// newTLSACache returns a cache. maxEntries <= 0 means 10000; a nil now
// means time.Now.
func newTLSACache(lookup lookupFunc, maxEntries int, now func() time.Time) *tlsaCache {
	if maxEntries <= 0 {
		maxEntries = defaultCacheEntries
	}
	if now == nil {
		now = time.Now
	}
	return &tlsaCache{
		lookup:     lookup,
		maxEntries: maxEntries,
		now:        now,
		entries:    make(map[string]cacheEntry),
	}
}

func cacheKey(qname string) string {
	return strings.ToLower(strings.TrimSuffix(qname, ".")) + "."
}

// Lookup returns the RRset or error for qname, and whether it came from
// the cache.
func (c *tlsaCache) Lookup(ctx context.Context, qname string) (rrset *dane.RRset, cached bool, err error) {
	key := cacheKey(qname)
	now := c.now()

	c.mu.Lock()
	if e, ok := c.entries[key]; ok {
		if now.Before(e.expires) {
			c.mu.Unlock()
			return e.rrset, true, e.err
		}
		delete(c.entries, key)
	}
	c.mu.Unlock()

	rrset, err = c.lookup(ctx, qname)

	var ttl time.Duration
	switch {
	case err == nil:
		if rrset != nil {
			ttl = time.Duration(rrset.TTL) * time.Second
		}
	case errors.Is(err, dane.ErrNXDOMAIN), errors.Is(err, dane.ErrNoData), errors.Is(err, dane.ErrInsecure):
		ttl = defaultNegTTL
		var le *dane.LookupError
		if errors.As(err, &le) && le.NegTTL > 0 {
			ttl = time.Duration(le.NegTTL) * time.Second
		}
	}
	if ttl > maxCacheTTL {
		ttl = maxCacheTTL
	}
	if ttl > 0 {
		c.store(key, cacheEntry{rrset: rrset, err: err, expires: c.now().Add(ttl)})
	}
	return rrset, false, err
}

func (c *tlsaCache) store(key string, e cacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.entries[key]; !exists {
		for len(c.entries) >= c.maxEntries {
			var victim string
			var first = true
			var soonest time.Time
			for k, v := range c.entries {
				if first || v.expires.Before(soonest) {
					victim, soonest, first = k, v.expires, false
				}
			}
			delete(c.entries, victim)
		}
	}
	c.entries[key] = e
}
