package gateway

import (
	"net/netip"
	"testing"
	"time"
)

func TestIPLimiterPerAddressAndIPv6Prefix(t *testing.T) {
	l := newIPLimiter(60, 2) // 1/s, burst 2
	now := time.Now()
	a := netip.MustParseAddr("192.0.2.1")
	b := netip.MustParseAddr("192.0.2.2")
	for i := range 2 {
		if !l.Allow(a, now) {
			t.Fatalf("burst request %d refused", i+1)
		}
	}
	if l.Allow(a, now) {
		t.Fatal("limit not enforced")
	}
	if !l.Allow(b, now) {
		t.Fatal("other address limited")
	}
	if !l.Allow(a, now.Add(1100*time.Millisecond)) {
		t.Fatal("bucket did not refill")
	}
	// Addresses in the same IPv6 /64 share a bucket.
	v1 := netip.MustParseAddr("2001:db8::1")
	v2 := netip.MustParseAddr("2001:db8::ffff")
	l.Allow(v1, now)
	l.Allow(v2, now)
	if l.Allow(v1, now) {
		t.Fatal("IPv6 /64 not grouped")
	}
}
