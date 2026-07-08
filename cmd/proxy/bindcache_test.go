package proxy

import (
	"testing"
	"time"

	"github.com/nmcclain/ldap"
)

func TestCredHash(t *testing.T) {
	a := credHash("cn=admin", "secret")
	if a != credHash("cn=admin", "secret") {
		t.Fatal("credHash must be stable for identical credentials")
	}
	if a == credHash("cn=admin", "other") {
		t.Fatal("credHash must depend on the password")
	}
	if a == credHash("cn=other", "secret") {
		t.Fatal("credHash must depend on the bind DN")
	}
}

func TestBindCacheKnownRemember(t *testing.T) {
	c := newBindCache(time.Minute, 4)

	ch := credHash("cn=admin", "secret")
	if c.known(ch) {
		t.Fatal("unknown credentials must not be reported as known")
	}

	c.remember(ch)
	if !c.known(ch) {
		t.Fatal("credentials must be known after remember")
	}
}

func TestBindCacheBorrowRelease(t *testing.T) {
	c := newBindCache(time.Minute, 4)

	ch := credHash("cn=admin", "secret")
	if _, ok := c.borrow(ch); ok {
		t.Fatal("borrow from empty pool must miss")
	}

	conn := &ldap.Conn{}
	if !c.release(ch, conn, time.Now()) {
		t.Fatal("release into an empty pool must succeed")
	}

	got, ok := c.borrow(ch)
	if !ok || got != conn {
		t.Fatal("borrow must return the released connection")
	}

	if _, ok := c.borrow(ch); ok {
		t.Fatal("connection must not be handed out twice")
	}
}

func TestBindCacheReleaseRejectsWhenFull(t *testing.T) {
	c := newBindCache(time.Minute, 2)
	ch := credHash("cn=admin", "secret")

	if !c.release(ch, &ldap.Conn{}, time.Now()) || !c.release(ch, &ldap.Conn{}, time.Now()) {
		t.Fatal("releases up to maxPerCred must succeed")
	}
	if c.release(ch, &ldap.Conn{}, time.Now()) {
		t.Fatal("release beyond maxPerCred must be rejected")
	}
}

func TestBindCacheReleaseRejectsStale(t *testing.T) {
	c := newBindCache(time.Minute, 4)
	ch := credHash("cn=admin", "secret")

	if c.release(ch, &ldap.Conn{}, time.Now().Add(-2*time.Minute)) {
		t.Fatal("a connection older than the TTL must not be pooled")
	}
}

func TestBindCacheDisabled(t *testing.T) {
	c := newBindCache(0, 4)
	if c.enabled() {
		t.Fatal("zero TTL must disable the bind cache")
	}

	ch := credHash("cn=admin", "secret")
	c.remember(ch)
	if c.known(ch) {
		t.Fatal("disabled bind cache must never report known")
	}
	if c.release(ch, &ldap.Conn{}, time.Now()) {
		t.Fatal("disabled bind cache must not pool connections")
	}
	if _, ok := c.borrow(ch); ok {
		t.Fatal("disabled bind cache must not hand out connections")
	}
}
