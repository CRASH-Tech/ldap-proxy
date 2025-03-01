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
	sessions map[string]session
	lock     sync.Mutex
	conf     config.Config
}

func connID(conn net.Conn) string {
	h := sha256.New()
	h.Write([]byte(conn.LocalAddr().String() + conn.RemoteAddr().String()))
	sha := fmt.Sprintf("% x", h.Sum(nil))
	return string(sha)
}

func (h ldapHandler) getSession(conn net.Conn) (session, error) {
	id := connID(conn)
	h.lock.Lock()
	s, ok := h.sessions[id]
	h.lock.Unlock()
	if !ok {
		l, err := ldap.Dial("tcp", h.conf.LdapServer)
		if err != nil {
			return session{}, err
		}
		s = session{id: id, c: conn, ldap: l}
		h.lock.Lock()
		h.sessions[s.id] = s
		h.lock.Unlock()
	}
	return s, nil
}

func (h ldapHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (ldap.LDAPResultCode, error) {
	s, err := h.getSession(conn)
	if err != nil {
		return ldap.LDAPResultOperationsError, err
	}
	if err := s.ldap.Bind(bindDN, bindSimplePw); err != nil {
		return ldap.LDAPResultOperationsError, err
	}
	return ldap.LDAPResultSuccess, nil
}

func (h ldapHandler) Search(boundDN string, searchReq ldap.SearchRequest, conn net.Conn) (ldap.ServerSearchResult, error) {
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

func (h ldapHandler) Close(boundDN string, conn net.Conn) error {
	conn.Close()
	h.lock.Lock()
	defer h.lock.Unlock()
	delete(h.sessions, connID(conn))
	return nil
}
