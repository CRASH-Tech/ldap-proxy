package proxy

import (
	"crypto/sha256"
	"fmt"
	"log"
	"net"
	"regexp"
	"strings"
	"sync"

	"github.com/CRASH-Tech/ldap-proxy/cmd/config"
	"github.com/nmcclain/ldap"
)

type session struct {
	id   string
	c    net.Conn
	ldap *ldap.Conn
}

type ldapHandler struct {
	sessions     map[string]session
	sessionQueue []string
	lock         sync.RWMutex
	conf         config.Config
}

func connID(conn net.Conn) string {
	h := sha256.New()
	h.Write([]byte(conn.LocalAddr().String() + conn.RemoteAddr().String()))
	sha := fmt.Sprintf("% x", h.Sum(nil))
	return string(sha)
}

func (h *ldapHandler) getSession(conn net.Conn) (session, error) {
	id := connID(conn)

	h.lock.RLock()
	s, ok := h.sessions[id]
	h.lock.RUnlock()

	if !ok {
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
			return session{}, err
		}
		s = session{id: id, c: conn, ldap: l}
		h.sessions[id] = s
		h.sessionQueue = append(h.sessionQueue, id)
	}

	return s, nil
}

func (h *ldapHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (ldap.LDAPResultCode, error) {
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
	s, err := h.getSession(conn)
	if err != nil {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, nil
	}

	f := searchReq.Filter

	if strings.Contains(searchReq.Filter, "objectClass=group") && strings.Contains(searchReq.Filter, "sudoUser=") {
		re := regexp.MustCompile(`sudoUser=([\w\.\-%#]+)`)
		f = re.ReplaceAllStringFunc(searchReq.Filter, func(match string) string {
			username := re.ReplaceAllString(match, "$1")
			return fmt.Sprintf("member=cn=%s,%s", username, h.conf.UsersDN)
		})
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

	log.Printf("P: Search OK: %s -> num of entries = %d\n", f, len(sr.Entries))

	return ldap.ServerSearchResult{sr.Entries, []string{}, []ldap.Control{}, ldap.LDAPResultSuccess}, nil
}

func (h *ldapHandler) Close(boundDN string, conn net.Conn) error {
	h.lock.Lock()
	defer h.lock.Unlock()

	id := connID(conn)
	if s, ok := h.sessions[id]; ok {
		log.Printf("Close connection: %s", s.c.RemoteAddr())

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
