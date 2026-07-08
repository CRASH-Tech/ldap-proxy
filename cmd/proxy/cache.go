package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"log"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nmcclain/ldap"
)

// cacheEntry holds a cached search result together with its expiration time.
type cacheEntry struct {
	entries   []*ldap.Entry
	expiresAt time.Time
}

// searchCache is an in-memory TTL cache for LDAP search results. It is safe
// for concurrent use. A zero or negative ttl disables caching entirely, in
// which case get always misses and set is a no-op.
type searchCache struct {
	ttl   time.Duration
	lock  sync.RWMutex
	items map[string]cacheEntry
}

// newSearchCache creates a cache with the given time-to-live. When ttl is
// positive a background janitor is started to evict expired entries so the
// map does not grow without bound.
func newSearchCache(ttl time.Duration) *searchCache {
	c := &searchCache{
		ttl:   ttl,
		items: make(map[string]cacheEntry),
	}
	if c.enabled() {
		go c.janitor()
	}
	return c
}

// enabled reports whether caching is turned on.
func (c *searchCache) enabled() bool {
	return c.ttl > 0
}

// cacheKey builds a stable key for a search request from the query itself: the
// base DN, the (already rewritten) filter, the scope and the requested
// attribute set. Attributes are sorted so that requests asking for the same set
// in a different order hit the same entry.
//
// The key deliberately does not include the bound identity, so identical
// queries issued by different clients share a cache entry. This assumes the
// upstream returns the same result regardless of who is bound (e.g. the queried
// attributes are world-readable), which holds for this proxy's use cases.
func cacheKey(baseDN, filter string, scope int, attrs []string) string {
	sorted := append([]string(nil), attrs...)
	sort.Strings(sorted)

	h := sha256.New()
	for _, part := range []string{baseDN, filter, strconv.Itoa(scope), strings.Join(sorted, ",")} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// get returns the cached entries for key when present and not expired.
func (c *searchCache) get(key string) ([]*ldap.Entry, bool) {
	if !c.enabled() {
		return nil, false
	}

	c.lock.RLock()
	entry, ok := c.items[key]
	c.lock.RUnlock()

	if !ok || time.Now().After(entry.expiresAt) {
		return nil, false
	}
	return entry.entries, true
}

// set stores entries for key with the configured TTL.
func (c *searchCache) set(key string, entries []*ldap.Entry) {
	if !c.enabled() {
		return
	}

	c.lock.Lock()
	c.items[key] = cacheEntry{
		entries:   entries,
		expiresAt: time.Now().Add(c.ttl),
	}
	c.lock.Unlock()
}

// janitor periodically removes expired entries from the cache.
func (c *searchCache) janitor() {
	ticker := time.NewTicker(c.ttl)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		removed := 0
		c.lock.Lock()
		for k, v := range c.items {
			if now.After(v.expiresAt) {
				delete(c.items, k)
				removed++
			}
		}
		remaining := len(c.items)
		c.lock.Unlock()

		if removed > 0 {
			log.Printf("P: Search cache cleanup: removed %d expired entries, %d remaining", removed, remaining)
		}
	}
}
