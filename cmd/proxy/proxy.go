package proxy

import (
	"log"

	"github.com/CRASH-Tech/ldap-proxy/cmd/config"
	"github.com/nmcclain/ldap"
)

type Proxy struct {
	conf config.Config
}

func New(conf config.Config) *Proxy {
	proxy := Proxy{
		conf: conf,
	}

	return &proxy
}

func (p Proxy) Start() {
	s := ldap.NewServer()

	handler := ldapHandler{
		sessions: make(map[string]session),
		conf:     p.conf,
	}
	s.BindFunc("", handler)
	s.SearchFunc("", handler)
	s.CloseFunc("", handler)

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
