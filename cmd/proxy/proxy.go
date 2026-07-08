// Package proxy implements an LDAP proxy that forwards bind and search
// requests to an upstream server, with query rewriting, response caching,
// connection pooling and per-IP rate limiting.
package proxy

import (
	"log"

	"github.com/CRASH-Tech/ldap-proxy/cmd/config"
	"github.com/nmcclain/ldap"
)

// Proxy is the top-level LDAP proxy server.
type Proxy struct {
	conf config.Config
}

// New creates a Proxy from the given configuration.
func New(conf config.Config) *Proxy {
	proxy := Proxy{
		conf: conf,
	}

	return &proxy
}

// Start builds the LDAP handler and serves requests, blocking until the server
// stops. It terminates the process if the listener fails to start.
func (p Proxy) Start() {
	s := ldap.NewServer()

	handler := ldapHandler{
		sessions:     make(map[string]session),
		conf:         p.conf,
		sessionQueue: []string{},
		ipStates:     make(map[string]*ipState),
		cache:        newSearchCache(p.conf.CacheTTL),
	}
	s.BindFunc("", &handler)
	s.SearchFunc("", &handler)
	s.CloseFunc("", &handler)

	if p.conf.UseTLS {
		if err := s.ListenAndServeTLS(p.conf.Listen, p.conf.CertFile, p.conf.CertKeyFile); err != nil {
			log.Fatalf("LDAP Server Failed: %s", err.Error())
		}
	} else {
		if err := s.ListenAndServe(p.conf.Listen); err != nil {
			log.Fatalf("LDAP Server Failed: %s", err.Error())
		}
	}

}
