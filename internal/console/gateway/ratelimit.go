package gateway

import (
	"net/netip"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// ipLimiter applies a token bucket per source IP. IPv6 addresses are grouped
// by /64, since a single host usually controls a whole /64.
type ipLimiter struct {
	mu      sync.Mutex
	limit   rate.Limit
	burst   int
	entries map[netip.Prefix]*limiterEntry
	maxSize int
}

type limiterEntry struct {
	lim      *rate.Limiter
	lastSeen time.Time
}

func newIPLimiter(perMinute float64, burst int) *ipLimiter {
	return &ipLimiter{
		limit:   rate.Limit(perMinute / 60),
		burst:   burst,
		entries: map[netip.Prefix]*limiterEntry{},
		maxSize: 100_000,
	}
}

func bucketFor(ip netip.Addr) netip.Prefix {
	if ip.Is4() {
		return netip.PrefixFrom(ip, 32)
	}
	p, _ := ip.Prefix(64)
	return p
}

func (l *ipLimiter) Allow(ip netip.Addr, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	key := bucketFor(ip)
	e, ok := l.entries[key]
	if !ok {
		if len(l.entries) >= l.maxSize {
			l.evict(now)
		}
		e = &limiterEntry{lim: rate.NewLimiter(l.limit, l.burst)}
		l.entries[key] = e
	}
	e.lastSeen = now
	return e.lim.AllowN(now, 1)
}

// evict drops entries idle long enough for their bucket to be full again; if
// that frees nothing, it resets the table rather than growing without bound.
func (l *ipLimiter) evict(now time.Time) {
	idle := time.Duration(float64(l.burst)/float64(l.limit)) * time.Second
	for k, e := range l.entries {
		if now.Sub(e.lastSeen) > idle {
			delete(l.entries, k)
		}
	}
	if len(l.entries) >= l.maxSize {
		l.entries = map[netip.Prefix]*limiterEntry{}
	}
}
