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

func TestConnPoolBorrowRelease(t *testing.T) {
	c := newConnPool(time.Minute, 4)

	ch := credHash("cn=admin", "secret")
	if _, _, ok := c.borrow(ch); ok {
		t.Fatal("borrow from empty pool must miss")
	}

	conn := &ldap.Conn{}
	boundAt := time.Now()
	if !c.release(ch, conn, boundAt) {
		t.Fatal("release into an empty pool must succeed")
	}

	got, gotBoundAt, ok := c.borrow(ch)
	if !ok || got != conn {
		t.Fatal("borrow must return the released connection")
	}
	if !gotBoundAt.Equal(boundAt) {
		t.Fatal("borrow must return the original bind time")
	}

	if _, _, ok := c.borrow(ch); ok {
		t.Fatal("connection must not be handed out twice")
	}
}

// TestConnPoolTTLFromRealBind proves that reuse does not extend a connection's
// lifetime: once it has outlived the TTL measured from its original bind, it is
// neither pooled nor handed out, even if it keeps being released.
func TestConnPoolTTLFromRealBind(t *testing.T) {
	c := newConnPool(30*time.Millisecond, 4)
	ch := credHash("cn=admin", "secret")

	boundAt := time.Now()
	if !c.release(ch, &ldap.Conn{}, boundAt) {
		t.Fatal("fresh connection must be poolable")
	}

	// A borrow within the TTL succeeds but keeps the original bind time.
	_, gotBoundAt, ok := c.borrow(ch)
	if !ok || !gotBoundAt.Equal(boundAt) {
		t.Fatal("reuse must preserve the original bind time")
	}

	// Simulate the connection being reused right up to the edge of the TTL:
	// releasing it again with its ORIGINAL bind time (never refreshed) must be
	// rejected once that time is older than the TTL.
	time.Sleep(40 * time.Millisecond)
	if c.release(ch, &ldap.Conn{}, boundAt) {
		t.Fatal("a connection past its TTL must not be pooled, even under constant reuse")
	}
	if _, _, ok := c.borrow(ch); ok {
		t.Fatal("nothing must be borrowable after the TTL")
	}
}

func TestConnPoolReleaseRejectsWhenFull(t *testing.T) {
	c := newConnPool(time.Minute, 2)
	ch := credHash("cn=admin", "secret")

	if !c.release(ch, &ldap.Conn{}, time.Now()) || !c.release(ch, &ldap.Conn{}, time.Now()) {
		t.Fatal("releases up to maxPerCred must succeed")
	}
	if c.release(ch, &ldap.Conn{}, time.Now()) {
		t.Fatal("release beyond maxPerCred must be rejected")
	}
}

func TestConnPoolReleaseRejectsStale(t *testing.T) {
	c := newConnPool(time.Minute, 4)
	ch := credHash("cn=admin", "secret")

	if c.release(ch, &ldap.Conn{}, time.Now().Add(-2*time.Minute)) {
		t.Fatal("a connection older than the TTL must not be pooled")
	}
}

func TestConnPoolDisabled(t *testing.T) {
	c := newConnPool(0, 4)
	if c.enabled() {
		t.Fatal("zero TTL must disable the connection pool")
	}

	ch := credHash("cn=admin", "secret")
	if c.release(ch, &ldap.Conn{}, time.Now()) {
		t.Fatal("disabled pool must not pool connections")
	}
	if _, _, ok := c.borrow(ch); ok {
		t.Fatal("disabled pool must not hand out connections")
	}
}
