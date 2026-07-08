package proxy

import (
	"testing"
	"time"

	"github.com/nmcclain/ldap"
)

func TestSearchCacheHitAndMiss(t *testing.T) {
	c := newSearchCache(time.Minute)

	key := cacheKey("cn=admin", "dc=example,dc=com", "(uid=jdoe)", 2, []string{"cn", "uid"})
	if _, ok := c.get(key); ok {
		t.Fatal("expected miss on empty cache")
	}

	entries := []*ldap.Entry{{DN: "cn=jdoe,dc=example,dc=com"}}
	c.set(key, entries)

	got, ok := c.get(key)
	if !ok {
		t.Fatal("expected hit after set")
	}
	if len(got) != 1 || got[0].DN != "cn=jdoe,dc=example,dc=com" {
		t.Fatalf("unexpected cached entries: %+v", got)
	}
}

func TestSearchCacheExpiry(t *testing.T) {
	c := newSearchCache(20 * time.Millisecond)

	key := cacheKey("", "dc=example,dc=com", "(objectClass=*)", 2, nil)
	c.set(key, []*ldap.Entry{{DN: "a"}})

	if _, ok := c.get(key); !ok {
		t.Fatal("expected hit before expiry")
	}

	time.Sleep(40 * time.Millisecond)

	if _, ok := c.get(key); ok {
		t.Fatal("expected miss after expiry")
	}
}

func TestSearchCacheDisabled(t *testing.T) {
	c := newSearchCache(0)
	if c.enabled() {
		t.Fatal("cache with zero ttl must be disabled")
	}

	key := cacheKey("", "dc=example,dc=com", "(objectClass=*)", 2, nil)
	c.set(key, []*ldap.Entry{{DN: "a"}})
	if _, ok := c.get(key); ok {
		t.Fatal("disabled cache must always miss")
	}
}

func TestCacheKeyAttributeOrderIndependent(t *testing.T) {
	k1 := cacheKey("dn", "base", "(uid=x)", 2, []string{"cn", "mail"})
	k2 := cacheKey("dn", "base", "(uid=x)", 2, []string{"mail", "cn"})
	if k1 != k2 {
		t.Fatal("cache key must not depend on attribute order")
	}

	k3 := cacheKey("dn2", "base", "(uid=x)", 2, []string{"cn", "mail"})
	if k1 == k3 {
		t.Fatal("cache key must depend on boundDN")
	}
}
