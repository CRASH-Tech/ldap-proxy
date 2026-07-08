package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"github.com/nmcclain/ldap"
)

// credHash derives a stable, non-reversible key from bind credentials. The
// password is part of the hash, so only a client that presents the exact same
// bindDN and password produces the same key — reusing a pooled connection for a
// matching key therefore never bypasses authentication.
func credHash(bindDN, password string) string {
	h := sha256.New()
	h.Write([]byte(bindDN))
	h.Write([]byte{0})
	h.Write([]byte(password))
	return hex.EncodeToString(h.Sum(nil))
}

// pooledConn is an authenticated upstream connection kept for later reuse.
type pooledConn struct {
	conn    *ldap.Conn
	boundAt time.Time
}

// bindCache remembers recently validated credentials and keeps a pool of
// already-authenticated upstream connections keyed by credentials. This lets
// repeated logins with the same credentials reuse a live bound connection
// instead of paying for a fresh upstream dial+bind on every request.
//
// A zero or negative ttl disables it entirely. Safe for concurrent use.
type bindCache struct {
	ttl        time.Duration
	maxPerCred int

	lock  sync.Mutex
	valid map[string]time.Time    // credHash -> bind result expiry
	pool  map[string][]pooledConn // credHash -> idle authenticated connections
}

// newBindCache creates a bind cache with the given TTL. maxPerCred bounds how
// many idle connections are pooled per distinct credential. When the TTL is
// positive a background janitor evicts expired entries and stale connections.
func newBindCache(ttl time.Duration, maxPerCred int) *bindCache {
	if maxPerCred < 1 {
		maxPerCred = 1
	}
	c := &bindCache{
		ttl:        ttl,
		maxPerCred: maxPerCred,
		valid:      make(map[string]time.Time),
		pool:       make(map[string][]pooledConn),
	}
	if c.enabled() {
		go c.janitor()
	}
	return c
}

// enabled reports whether bind caching / connection pooling is turned on.
func (c *bindCache) enabled() bool {
	return c.ttl > 0
}

// known reports whether the given credentials were successfully validated
// within the TTL window.
func (c *bindCache) known(credHash string) bool {
	if !c.enabled() {
		return false
	}
	c.lock.Lock()
	defer c.lock.Unlock()

	exp, ok := c.valid[credHash]
	return ok && time.Now().Before(exp)
}

// remember records that credHash was successfully bound, refreshing its TTL.
func (c *bindCache) remember(credHash string) {
	if !c.enabled() {
		return
	}
	c.lock.Lock()
	c.valid[credHash] = time.Now().Add(c.ttl)
	c.lock.Unlock()
}

// borrow returns a fresh idle authenticated connection for credHash if one is
// available. The returned connection is removed from the pool and owned by the
// caller until it is released again. Stale connections are closed and skipped.
func (c *bindCache) borrow(credHash string) (*ldap.Conn, bool) {
	if !c.enabled() {
		return nil, false
	}
	c.lock.Lock()
	defer c.lock.Unlock()

	conns := c.pool[credHash]
	for len(conns) > 0 {
		last := conns[len(conns)-1]
		conns = conns[:len(conns)-1]
		if time.Since(last.boundAt) < c.ttl {
			c.pool[credHash] = conns
			return last.conn, true
		}
		last.conn.Close() // expired: discard
	}
	delete(c.pool, credHash)
	return nil, false
}

// release returns an authenticated connection to the pool for reuse. It reports
// whether the connection was accepted; when it returns false the caller must
// close the connection itself (caching disabled, no credentials, connection too
// old, or the pool for this credential is full).
func (c *bindCache) release(credHash string, conn *ldap.Conn, boundAt time.Time) bool {
	if !c.enabled() || credHash == "" {
		return false
	}
	if time.Since(boundAt) >= c.ttl {
		return false
	}
	c.lock.Lock()
	defer c.lock.Unlock()

	if len(c.pool[credHash]) >= c.maxPerCred {
		return false
	}
	c.pool[credHash] = append(c.pool[credHash], pooledConn{conn: conn, boundAt: boundAt})
	return true
}

// janitor periodically drops expired credentials and closes stale pooled
// connections so neither map grows without bound.
func (c *bindCache) janitor() {
	ticker := time.NewTicker(c.ttl)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		c.lock.Lock()
		for k, exp := range c.valid {
			if now.After(exp) {
				delete(c.valid, k)
			}
		}
		for k, conns := range c.pool {
			kept := conns[:0]
			for _, pc := range conns {
				if now.Sub(pc.boundAt) < c.ttl {
					kept = append(kept, pc)
				} else {
					pc.conn.Close()
				}
			}
			if len(kept) == 0 {
				delete(c.pool, k)
			} else {
				c.pool[k] = kept
			}
		}
		c.lock.Unlock()
	}
}
