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

type session struct {
	id   string
	c    net.Conn
	ldap *ldap.Conn
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

		if len(h.sessionQueue) >= h.conf.MaxSessions {
			oldestID := h.sessionQueue[0]
			h.sessionQueue = h.sessionQueue[1:]

			if oldSession, exists := h.sessions[oldestID]; exists {
				log.Printf("Close session: %s", oldSession.id)
				oldSession.ldap.Close()
				delete(h.sessions, oldestID)
			}
		}

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

func (h *ldapHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (ldap.LDAPResultCode, error) {
	ip := getIP(conn.RemoteAddr())
	if !h.checkRateLimit(ip) {
		log.Printf("Rate limit exceeded for IP %s", ip)
		return ldap.LDAPResultOperationsError, errors.New("rate limit exceeded")
	}

	log.Printf("New bind connection for: %s", conn.RemoteAddr())
	s, err := h.getSession(conn)
	if err != nil {
		return ldap.LDAPResultOperationsError, err
	}
	if err := s.ldap.Bind(bindDN, bindSimplePw); err != nil {
		return ldap.LDAPResultOperationsError, err
	}

	return ldap.LDAPResultSuccess, nil
}

func (h *ldapHandler) Search(boundDN string, searchReq ldap.SearchRequest, conn net.Conn) (ldap.ServerSearchResult, error) {
	ip := getIP(conn.RemoteAddr())
	if !h.checkRateLimit(ip) {
		log.Printf("Rate limit exceeded for IP %s", ip)
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, errors.New("rate limit exceeded")
	}

	s, err := h.getSession(conn)
	if err != nil {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, err
	}

	f := searchReq.Filter

	if strings.Contains(searchReq.Filter, "objectClass=group") && strings.Contains(searchReq.Filter, "sudoUser=") {
		re := regexp.MustCompile(`sudoUser=([\w\.\-%#]+)`)
		f = re.ReplaceAllStringFunc(searchReq.Filter, func(match string) string {
			username := re.ReplaceAllString(match, "$1")
			return fmt.Sprintf("member=cn=%s,%s", username, h.conf.UsersDN)
		})
	}

	key := cacheKey(boundDN, searchReq.BaseDN, f, int(searchReq.Scope), searchReq.Attributes)
	if entries, ok := h.cache.get(key); ok {
		log.Printf("P: Search CACHE HIT: %s -> num of entries = %d\n", f, len(entries))
		return ldap.ServerSearchResult{entries, []string{}, []ldap.Control{}, ldap.LDAPResultSuccess}, nil
	}

	search := ldap.NewSearchRequest(
		searchReq.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		f,
		searchReq.Attributes,
		nil)
	sr, err := s.ldap.Search(search)
	if err != nil {
		return ldap.ServerSearchResult{}, err
	}

	h.cache.set(key, sr.Entries)

	log.Printf("P: Search OK: %s -> num of entries = %d\n", f, len(sr.Entries))

	return ldap.ServerSearchResult{sr.Entries, []string{}, []ldap.Control{}, ldap.LDAPResultSuccess}, nil
}

func (h *ldapHandler) Close(boundDN string, conn net.Conn) error {
	h.lock.Lock()
	defer h.lock.Unlock()

	id := connID(conn)
	if s, ok := h.sessions[id]; ok {
		log.Printf("Close connection: %s", s.c.RemoteAddr())
		h.releaseConnection(getIP(s.c.RemoteAddr()))

		s.ldap.Close()
		delete(h.sessions, id)

		for i, queuedID := range h.sessionQueue {
			if queuedID == id {
				h.sessionQueue = append(h.sessionQueue[:i], h.sessionQueue[i+1:]...)
				break
			}
		}
	}
	conn.Close()

	return nil
}
