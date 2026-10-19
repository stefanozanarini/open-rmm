// Package accesslog defines the logon events reported by the accesslog
// module, normalizes them and detects unusual logons.
package accesslog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"
)

// Module and action whose results are logon events.
const (
	ModuleID = "accesslog"
	Action   = "collect"
)

const (
	maxEvents = 10000
	maxString = 256
)

// Event kinds.
const (
	KindLogon           = "logon"             // Security 4624
	KindLogonFailed     = "logon_failed"      // Security 4625
	KindLockout         = "lockout"           // Security 4740
	KindRDPAuth         = "rdp_auth"          // RemoteConnectionManager 1149
	KindRDPSessionLogon = "rdp_session_logon" // LocalSessionManager 21
	KindRDPDisconnect   = "rdp_disconnect"    // LocalSessionManager 24
	KindRDPReconnect    = "rdp_reconnect"     // LocalSessionManager 25
)

var kinds = map[string]bool{KindLogon: true, KindLogonFailed: true, KindLockout: true, KindRDPAuth: true,
	KindRDPSessionLogon: true, KindRDPDisconnect: true, KindRDPReconnect: true}

var channels = map[string]bool{"security": true, "rcm": true, "lsm": true}

// Event is one logon event.
type Event struct {
	Channel    string    `json:"channel"`
	RecordID   int64     `json:"record_id"`
	Time       time.Time `json:"time"`
	EventID    int       `json:"event_id"`
	Kind       string    `json:"kind"`
	User       string    `json:"user,omitempty"`
	Domain     string    `json:"domain,omitempty"`
	LogonType  int       `json:"logon_type,omitempty"`
	SourceIP   string    `json:"source_ip,omitempty"`
	SourceHost string    `json:"source_host,omitempty"`
	Status     string    `json:"status,omitempty"`
}

// Result is what the module returns.
type Result struct {
	Events    []Event `json:"events"`
	Truncated bool    `json:"truncated,omitempty"`
}

func clip(s string) string {
	s = strings.TrimSpace(strings.ToValidUTF8(s, ""))
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if s == "-" {
		return ""
	}
	if len(s) > maxString {
		s = s[:maxString]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return s
}

// normalizeIP returns the canonical form of an IP address, or "" for
// values that are not addresses ("-", "LOCAL", host names).
func normalizeIP(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "::ffff:")
	a, err := netip.ParseAddr(s)
	if err != nil {
		return ""
	}
	return a.Unmap().WithZone("").String()
}

// Parse decodes a module result; invalid events are dropped.
func Parse(raw []byte) (*Result, error) {
	r := &Result{}
	if err := json.NewDecoder(bytes.NewReader(raw)).Decode(r); err != nil {
		return nil, fmt.Errorf("accesslog: %w", err)
	}
	if len(r.Events) > maxEvents {
		r.Events, r.Truncated = r.Events[:maxEvents], true
	}
	out := r.Events[:0]
	for _, e := range r.Events {
		if !channels[e.Channel] || !kinds[e.Kind] || e.RecordID <= 0 || e.Time.IsZero() || e.EventID <= 0 || e.EventID > 65535 {
			continue
		}
		e.Time = e.Time.UTC()
		e.User, e.Domain, e.SourceHost, e.Status = clip(e.User), clip(e.Domain), clip(e.SourceHost), clip(e.Status)
		e.SourceIP = normalizeIP(e.SourceIP)
		e.LogonType = max(0, min(e.LogonType, 99))
		out = append(out, e)
	}
	r.Events = out
	return r, nil
}

// IsRDP reports whether a successful event is a remote desktop logon.
func IsRDP(kind string, logonType int) bool {
	switch kind {
	case KindRDPAuth, KindRDPSessionLogon, KindRDPReconnect:
		return true
	case KindLogon:
		return logonType == 10
	}
	return false
}

// DefaultAllowed are the networks RDP is expected from when the tenant has
// not configured its LAN subnets: private ranges and loopback.
var DefaultAllowed = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("::1/128"), netip.MustParsePrefix("fe80::/10"),
}

// ParseSubnets parses CIDR prefixes (one per entry); a bare address means /32 or /128.
func ParseSubnets(in []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if !strings.Contains(s, "/") {
			a, err := netip.ParseAddr(s)
			if err != nil {
				return nil, fmt.Errorf("%q is not an address or a subnet", s)
			}
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("%q is not a subnet (e.g. 192.168.10.0/24)", s)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// Allowed reports whether ip falls in one of the prefixes.
func Allowed(ip string, prefixes []netip.Prefix) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
