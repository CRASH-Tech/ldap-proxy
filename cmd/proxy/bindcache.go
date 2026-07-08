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

// pooledConn is an authenticated upstream connection kept for later reuse,
// together with the moment it was actually authenticated against the upstream.
type pooledConn struct {
	conn    *ldap.Conn
	boundAt time.Time
}

// connPool keeps authenticated upstream connections keyed by credentials so
// repeated logins with the same credentials can reuse a live bound connection
// instead of dialing and binding again.
//
// Reuse is bounded by a TTL measured from the moment a connection was actually
// authenticated against the upstream. That timestamp (boundAt) is preserved
// across reuse and never refreshed, so a connection is retired — and the client
// re-validated upstream on its next login — at most ttl after its real bind,
// even under constant load. A zero or negative ttl disables pooling. Safe for
// concurrent use.
type connPool struct {
	ttl        time.Duration
	maxPerCred int

	lock sync.Mutex
	pool map[string][]pooledConn // credHash -> idle authenticated connections
}

// newConnPool creates a pool with the given TTL. maxPerCred bounds how many
// idle connections are kept per distinct credential. When the TTL is positive a
// background janitor closes connections once they outlive it.
func newConnPool(ttl time.Duration, maxPerCred int) *connPool {
	if maxPerCred < 1 {
		maxPerCred = 1
	}
	c := &connPool{
		ttl:        ttl,
		maxPerCred: maxPerCred,
		pool:       make(map[string][]pooledConn),
	}
	if c.enabled() {
		go c.janitor()
	}
	return c
}

// enabled reports whether connection pooling is turned on.
func (c *connPool) enabled() bool {
	return c.ttl > 0
}

// borrow returns an idle authenticated connection for credHash together with
// the time it was originally bound. Connections that have outlived the TTL are
// closed and skipped, never handed out.
func (c *connPool) borrow(credHash string) (*ldap.Conn, time.Time, bool) {
	if !c.enabled() {
		return nil, time.Time{}, false
	}
	c.lock.Lock()
	defer c.lock.Unlock()

	conns := c.pool[credHash]
	for len(conns) > 0 {
		last := conns[len(conns)-1]
		conns = conns[:len(conns)-1]
		if time.Since(last.boundAt) < c.ttl {
			c.pool[credHash] = conns
			return last.conn, last.boundAt, true
		}
		last.conn.Close() // outlived its TTL: discard
	}
	delete(c.pool, credHash)
	return nil, time.Time{}, false
}

// release returns a connection to the pool for reuse, preserving its original
// bind time. It reports whether the connection was accepted; when it returns
// false the caller must close the connection itself (pooling disabled, empty
// credentials, connection already past its TTL, or the pool for this credential
// is full).
func (c *connPool) release(credHash string, conn *ldap.Conn, boundAt time.Time) bool {
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

// janitor periodically closes pooled connections that have outlived the TTL so
// the pool does not grow without bound and stale connections are not reused.
func (c *connPool) janitor() {
	ticker := time.NewTicker(c.ttl)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		c.lock.Lock()
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
