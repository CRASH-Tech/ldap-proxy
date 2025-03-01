package main

import (
	"github.com/CRASH-Tech/ldap-proxy/cmd/config"
	"github.com/CRASH-Tech/ldap-proxy/cmd/proxy"
)

func main() {
	conf := *config.New()
	proxy := proxy.New(conf)

	proxy.Start()
}
