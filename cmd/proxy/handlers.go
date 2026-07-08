package proxy

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/CRASH-Tech/ldap-proxy/cmd/config"
	"github.com/nmcclain/ldap"
	"golang.org/x/time/rate"
)

// session ties a client connection to its upstream LDAP connection.
type session struct {
	id       string
	c        net.Conn
	ldap     *ldap.Conn
	credHash string    // credential pool this upstream conn belongs to ("" = anonymous)
	boundAt  time.Time // when the upstream conn was last known authenticated
}

type ipState struct {
	conns   int
	limiter *rate.Limiter
}

type ldapHandler struct {
	sessions     map[string]session
	sessionQueue []string
	lock         sync.RWMutex
	conf         config.Config
	ipStates     map[string]*ipState
	ipLock       sync.Mutex
	cache        *searchCache
	binds        *bindCache
}

func connID(conn net.Conn) string {
	h := sha256.New()
	h.Write([]byte(conn.LocalAddr().String() + conn.RemoteAddr().String()))
	sha := fmt.Sprintf("% x", h.Sum(nil))
	return string(sha)
}

func getIP(addr net.Addr) string {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

func (h *ldapHandler) checkRateLimit(ip string) bool {
	h.ipLock.Lock()
	defer h.ipLock.Unlock()

	state, exists := h.ipStates[ip]
	if !exists {
		state = &ipState{
			conns:   0,
			limiter: rate.NewLimiter(rate.Limit(h.conf.MaxRPS), h.conf.MaxRPS),
		}
		h.ipStates[ip] = state
	}

	return state.limiter.Allow()
}

func (h *ldapHandler) trackConnection(ip string) error {
	h.ipLock.Lock()
	defer h.ipLock.Unlock()

	state, exists := h.ipStates[ip]
	if !exists {
		state = &ipState{
			conns:   0,
			limiter: rate.NewLimiter(rate.Limit(h.conf.MaxRPS), h.conf.MaxRPS),
		}
		h.ipStates[ip] = state
	}

	if state.conns >= h.conf.MaxConnsPerIP {
		return fmt.Errorf("too many connections from %s", ip)
	}

	state.conns++
	return nil
}

func (h *ldapHandler) releaseConnection(ip string) {
	h.ipLock.Lock()
	defer h.ipLock.Unlock()

	if state, exists := h.ipStates[ip]; exists {
		state.conns--
		if state.conns < 0 {
			state.conns = 0
		}
	}
}

// evictLocked drops the oldest session when the MaxSessions limit is reached,
// returning its upstream connection to the pool for reuse when possible. It
// must be called with h.lock held.
func (h *ldapHandler) evictLocked() {
	if len(h.sessionQueue) >= h.conf.MaxSessions {
		oldestID := h.sessionQueue[0]
		h.sessionQueue = h.sessionQueue[1:]

		if old, exists := h.sessions[oldestID]; exists {
			log.Printf("Close session: %s", old.id)
			h.retireUpstream(old)
			delete(h.sessions, oldestID)
		}
	}
}

// retireUpstream releases a session's upstream connection: it is returned to
// the authenticated pool when it still carries valid credentials, otherwise it
// is closed.
func (h *ldapHandler) retireUpstream(s session) {
	if s.ldap == nil {
		return
	}
	if h.binds.release(s.credHash, s.ldap, s.boundAt) {
		return
	}
	s.ldap.Close()
}

// getSession returns the existing session for a client connection, or creates a
// new one backed by a freshly dialed (unauthenticated) upstream connection.
func (h *ldapHandler) getSession(conn net.Conn) (session, error) {
	id := connID(conn)
	ip := getIP(conn.RemoteAddr())

	h.lock.RLock()
	s, ok := h.sessions[id]
	h.lock.RUnlock()

	if !ok {
		if err := h.trackConnection(ip); err != nil {
			log.Printf("Connection limit exceeded for IP %s", ip)
			return session{}, err
		}

		h.lock.Lock()
		defer h.lock.Unlock()

		// Another goroutine may have created the session while we waited.
		if existing, ok := h.sessions[id]; ok {
			h.releaseConnection(ip)
			conn.SetDeadline(time.Now().Add(h.conf.ConnTimeout))
			return existing, nil
		}

		h.evictLocked()

		log.Printf("New connection: %s", conn.RemoteAddr())
		l, err := ldap.Dial("tcp", h.conf.LdapServer)
		if err != nil {
			h.releaseConnection(ip)
			return session{}, err
		}
		s = session{id: id, c: conn, ldap: l}
		h.sessions[id] = s
		h.sessionQueue = append(h.sessionQueue, id)
	}

	conn.SetDeadline(time.Now().Add(h.conf.ConnTimeout))
	return s, nil
}

// attachSession installs an already-authenticated upstream connection as the
// session for a client connection, replacing any previous upstream connection.
func (h *ldapHandler) attachSession(conn net.Conn, upstream *ldap.Conn, credHash string) error {
	id := connID(conn)
	ip := getIP(conn.RemoteAddr())

	h.lock.Lock()
	defer h.lock.Unlock()

	if existing, ok := h.sessions[id]; ok {
		h.retireUpstream(existing)
		existing.ldap = upstream
		existing.credHash = credHash
		existing.boundAt = time.Now()
		h.sessions[id] = existing
		conn.SetDeadline(time.Now().Add(h.conf.ConnTimeout))
		return nil
	}

	if err := h.trackConnection(ip); err != nil {
		log.Printf("Connection limit exceeded for IP %s", ip)
		return err
	}

	h.evictLocked()

	s := session{id: id, c: conn, ldap: upstream, credHash: credHash, boundAt: time.Now()}
	h.sessions[id] = s
	h.sessionQueue = append(h.sessionQueue, id)
	conn.SetDeadline(time.Now().Add(h.conf.ConnTimeout))
	return nil
}

// setSessionCreds records the credentials a client connection is bound as so
// that its upstream connection can later be pooled for reuse.
func (h *ldapHandler) setSessionCreds(conn net.Conn, credHash string) {
	id := connID(conn)

	h.lock.Lock()
	defer h.lock.Unlock()

	if s, ok := h.sessions[id]; ok {
		s.credHash = credHash
		s.boundAt = time.Now()
		h.sessions[id] = s
	}
}

// invalidateSession marks a session's upstream connection as non-reusable, so a
// connection that has just failed (e.g. closed server-side) is torn down on
// close instead of being returned to the pool for the next client.
func (h *ldapHandler) invalidateSession(conn net.Conn) {
	id := connID(conn)

	h.lock.Lock()
	defer h.lock.Unlock()

	if s, ok := h.sessions[id]; ok {
		s.credHash = ""
		h.sessions[id] = s
	}
}

func (h *ldapHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (ldap.LDAPResultCode, error) {
	ip := getIP(conn.RemoteAddr())
	if !h.checkRateLimit(ip) {
		log.Printf("Rate limit exceeded for IP %s", ip)
		return ldap.LDAPResultOperationsError, errors.New("rate limit exceeded")
	}

	log.Printf("New bind connection for: %s", conn.RemoteAddr())

	ch := credHash(bindDN, bindSimplePw)

	// Fast path: reuse a pooled connection already authenticated with these
	// exact credentials, skipping the upstream dial+bind entirely.
	if upstream, ok := h.binds.borrow(ch); ok {
		if err := h.attachSession(conn, upstream, ch); err != nil {
			h.binds.release(ch, upstream, time.Now())
			return ldap.LDAPResultOperationsError, err
		}
		h.binds.remember(ch)
		log.Printf("P: Bind CACHE HIT (pooled) for %s", bindDN)
		return ldap.LDAPResultSuccess, nil
	}

	// Slow path: bind this client's own upstream connection.
	s, err := h.getSession(conn)
	if err != nil {
		return ldap.LDAPResultOperationsError, err
	}

	// The connection is already bound with the same, recently validated
	// credentials (client re-binding): no need to hit the upstream again.
	if s.credHash == ch && h.binds.known(ch) {
		log.Printf("P: Bind CACHE HIT (session) for %s", bindDN)
		return ldap.LDAPResultSuccess, nil
	}

	if err := s.ldap.Bind(bindDN, bindSimplePw); err != nil {
		// A failed bind must never leave the connection eligible for reuse.
		h.invalidateSession(conn)
		return ldap.LDAPResultOperationsError, err
	}

	h.setSessionCreds(conn, ch)
	h.binds.remember(ch)

	return ldap.LDAPResultSuccess, nil
}

func (h *ldapHandler) Search(boundDN string, searchReq ldap.SearchRequest, conn net.Conn) (ldap.ServerSearchResult, error) {
	ip := getIP(conn.RemoteAddr())
	if !h.checkRateLimit(ip) {
		log.Printf("Rate limit exceeded for IP %s", ip)
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, errors.New("rate limit exceeded")
	}

	f := searchReq.Filter

	if strings.Contains(searchReq.Filter, "objectClass=group") && strings.Contains(searchReq.Filter, "sudoUser=") {
		re := regexp.MustCompile(`sudoUser=([\w\.\-%#]+)`)
		f = re.ReplaceAllStringFunc(searchReq.Filter, func(match string) string {
			username := re.ReplaceAllString(match, "$1")
			return fmt.Sprintf("member=cn=%s,%s", username, h.conf.UsersDN)
		})
	}

	// Serve from cache before touching the upstream at all.
	key := cacheKey(searchReq.BaseDN, f, int(searchReq.Scope), searchReq.Attributes)
	if entries, ok := h.cache.get(key); ok {
		log.Printf("P: Search CACHE HIT: %s -> num of entries = %d\n", f, len(entries))
		return ldap.ServerSearchResult{entries, []string{}, []ldap.Control{}, ldap.LDAPResultSuccess}, nil
	}

	s, err := h.getSession(conn)
	if err != nil {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, err
	}

	search := ldap.NewSearchRequest(
		searchReq.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		f,
		searchReq.Attributes,
		nil)
	sr, err := s.ldap.Search(search)
	if err != nil {
		// The upstream connection may be stale (e.g. closed server-side after
		// pooling); make sure it is not handed back out for reuse.
		h.invalidateSession(conn)
		return ldap.ServerSearchResult{}, err
	}

	h.cache.set(key, sr.Entries)

	log.Printf("P: Search OK: %s -> num of entries = %d\n", f, len(sr.Entries))

	return ldap.ServerSearchResult{sr.Entries, []string{}, []ldap.Control{}, ldap.LDAPResultSuccess}, nil
}

func (h *ldapHandler) Close(boundDN string, conn net.Conn) error {
	h.lock.Lock()

	id := connID(conn)
	if s, ok := h.sessions[id]; ok {
		log.Printf("Close connection: %s", s.c.RemoteAddr())
		h.releaseConnection(getIP(s.c.RemoteAddr()))

		// Return the authenticated upstream connection to the pool for reuse
		// instead of tearing it down.
		h.retireUpstream(s)
		delete(h.sessions, id)

		for i, queuedID := range h.sessionQueue {
			if queuedID == id {
				h.sessionQueue = append(h.sessionQueue[:i], h.sessionQueue[i+1:]...)
				break
			}
		}
	}

	h.lock.Unlock()
	conn.Close()

	return nil
}
