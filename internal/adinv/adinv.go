// Package adinv parses the Active Directory computer list reported by the
// adinventory module and compares it with the agents: computers without an
// agent, stale computer objects, and the organizational unit of each agent.
// The report also names the enabled users, to find computers by the name of
// their user.
//
// The module runs on a domain member with the computer account's read
// access to the directory: the console holds no AD credentials.
package adinv

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"
)

const (
	ModuleID = "adinventory"
	Action   = "collect"

	// MaxComputers bounds a report (the module result is at most 3 MiB).
	MaxComputers = 10000
	// MaxUsers bounds the users of a report.
	MaxUsers = 20000

	// ActiveDays: a computer that logged on more recently is in use.
	ActiveDays = 30
	// StaleDays: an enabled computer that has not logged on for longer is
	// probably gone. lastLogonTimestamp replicates with up to 14 days of
	// delay, so shorter thresholds are not meaningful.
	StaleDays = 90
)

// Computer is a computer object.
type Computer struct {
	Name        string     `json:"name"` // NetBIOS name (sAMAccountName without $)
	DNSHostName string     `json:"dns_host_name,omitempty"`
	DN          string     `json:"dn"`
	OS          string     `json:"os,omitempty"`
	OSVersion   string     `json:"os_version,omitempty"`
	Enabled     bool       `json:"enabled"`
	LastLogon   *time.Time `json:"last_logon,omitempty"` // lastLogonTimestamp
	PwdLastSet  *time.Time `json:"pwd_last_set,omitempty"`
	Created     *time.Time `json:"created,omitempty"`
}

// Snapshot is one domain's computers.
type Snapshot struct {
	Schema      int        `json:"schema"`
	Domain      string     `json:"domain"` // DNS name
	CollectedAt time.Time  `json:"collected_at"`
	Computers   []Computer `json:"computers"`
	Truncated   bool       `json:"truncated,omitempty"`
	// Users: enabled accounts with a name (adinventory 1.1.0 and later).
	Users          []User `json:"users,omitempty"`
	UsersTruncated bool   `json:"users_truncated,omitempty"`
}

var (
	domainRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62}\.)*[a-z0-9-]{1,63}$`)
	nameRe   = regexp.MustCompile(`^[A-Z0-9][A-Z0-9._-]{0,63}$`)
)

// Parse validates and normalizes a report.
func Parse(raw []byte) (*Snapshot, error) {
	var s Snapshot
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	if s.Schema != 1 {
		return nil, fmt.Errorf("unsupported schema %d", s.Schema)
	}
	s.Domain = strings.ToLower(strings.TrimSuffix(s.Domain, "."))
	if len(s.Domain) > 253 || !domainRe.MatchString(s.Domain) {
		return nil, errors.New("invalid domain name")
	}
	if s.CollectedAt.IsZero() {
		return nil, errors.New("collected_at is required")
	}
	if len(s.Computers) > MaxComputers {
		return nil, fmt.Errorf("more than %d computers", MaxComputers)
	}
	out := s.Computers[:0]
	for _, c := range s.Computers {
		c.Name = strings.ToUpper(strings.TrimSuffix(strings.TrimSpace(c.Name), "$"))
		c.DNSHostName = strings.ToLower(c.DNSHostName)
		if !nameRe.MatchString(c.Name) || c.DN == "" || len(c.DN) > 1024 || len(c.DNSHostName) > 255 ||
			len(c.OS) > 128 || len(c.OSVersion) > 64 {
			continue
		}
		out = append(out, c)
	}
	s.Computers = out
	sort.Slice(s.Computers, func(i, j int) bool { return s.Computers[i].Name < s.Computers[j].Name })
	if len(s.Users) > MaxUsers {
		return nil, fmt.Errorf("more than %d users", MaxUsers)
	}
	users := s.Users[:0]
	for _, u := range s.Users {
		u.SAM, u.UPN = strings.TrimSpace(u.SAM), strings.TrimSpace(u.UPN)
		if u.SAM == "" || len(u.SAM) > 64 || len(u.UPN) > 256 || len(u.GivenName) > 128 || len(u.Surname) > 128 ||
			len(u.DisplayName) > 256 || strings.ContainsFunc(u.SAM+u.UPN+u.GivenName+u.Surname+u.DisplayName, unicode.IsControl) {
			continue
		}
		users = append(users, u)
	}
	s.Users = users
	return &s, nil
}

// User is an enabled user account.
type User struct {
	SAM         string `json:"sam"` // sAMAccountName
	UPN         string `json:"upn,omitempty"`
	GivenName   string `json:"given_name,omitempty"`
	Surname     string `json:"surname,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
}

// Names are the user's names, for search and display: the display name and,
// when it does not contain them, given name and surname.
func (u User) Names() []string {
	out := []string{u.DisplayName}
	low := strings.ToLower(u.DisplayName)
	for _, n := range []string{u.GivenName, u.Surname} {
		if n != "" && !strings.Contains(low, strings.ToLower(n)) {
			out = append(out, n)
		}
	}
	return slices.DeleteFunc(out, func(s string) bool { return s == "" })
}

// Label is how the user is shown: the display name, or given name and
// surname.
func (u User) Label() string {
	if u.DisplayName != "" {
		return u.DisplayName
	}
	return strings.TrimSpace(u.GivenName + " " + u.Surname)
}

// UserIndex finds the AD account of a user name as Windows reports it
// (DOMAIN\user, user@domain or user), by account name or UPN, lower case.
type UserIndex map[string]User

// NewUserIndex indexes the users of the snapshots.
func NewUserIndex(snaps []*Snapshot) UserIndex {
	idx := UserIndex{}
	for _, s := range snaps {
		for _, u := range s.Users {
			idx[strings.ToLower(u.SAM)] = u
			if u.UPN != "" {
				idx[strings.ToLower(u.UPN)] = u
			}
		}
	}
	return idx
}

// Lookup returns the account of a user name.
func (idx UserIndex) Lookup(name string) (User, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return User{}, false
	}
	if u, ok := idx[name]; ok {
		return u, true
	}
	if _, sam, ok := strings.Cut(name, `\`); ok {
		u, ok := idx[sam]
		return u, ok
	}
	if sam, _, ok := strings.Cut(name, "@"); ok {
		u, ok := idx[sam]
		return u, ok
	}
	return User{}, false
}

// splitDN splits a distinguished name into its RDNs, honoring escapes.
func splitDN(dn string) []string {
	var out []string
	var cur strings.Builder
	esc := false
	for _, r := range dn {
		switch {
		case esc:
			cur.WriteRune(r)
			esc = false
		case r == '\\':
			cur.WriteRune(r)
			esc = true
		case r == ',':
			out = append(out, strings.TrimSpace(cur.String()))
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	return append(out, strings.TrimSpace(cur.String()))
}

func unescape(v string) string {
	var b strings.Builder
	esc := false
	for _, r := range v {
		if !esc && r == '\\' {
			esc = true
			continue
		}
		esc = false
		b.WriteRune(r)
	}
	return b.String()
}

// OU returns the readable container path of the computer, from the domain
// down ("Sedi/Bologna/Computer"), or "" for the domain root.
func (c Computer) OU() string {
	rdns := splitDN(c.DN)
	var parts []string
	for _, rdn := range rdns[1:] { // the first RDN is the computer itself
		k, v, ok := strings.Cut(rdn, "=")
		if !ok {
			continue
		}
		switch strings.ToUpper(k) {
		case "OU", "CN":
			parts = append([]string{unescape(v)}, parts...)
		}
	}
	return strings.Join(parts, "/")
}

// lastSeen is the most recent sign of activity of the computer.
func (c Computer) lastSeen() time.Time {
	var t time.Time
	for _, x := range []*time.Time{c.LastLogon, c.PwdLastSet, c.Created} {
		if x != nil && x.After(t) {
			t = *x
		}
	}
	return t
}

// Active: enabled and in use recently.
func (c Computer) Active(now time.Time) bool {
	return c.Enabled && now.Sub(c.lastSeen()) <= ActiveDays*24*time.Hour
}

// Stale: enabled but unused for a long time.
func (c Computer) Stale(now time.Time) bool {
	return c.Enabled && now.Sub(c.lastSeen()) > StaleDays*24*time.Hour
}

// IdleDays is how long the computer has not been seen.
func (c Computer) IdleDays(now time.Time) int {
	t := c.lastSeen()
	if t.IsZero() {
		return -1
	}
	return int(now.Sub(t).Hours() / 24)
}

// HostKey is the key agents and computers are matched on: the first label of
// the host name, upper case.
func HostKey(hostname string) string {
	h, _, _ := strings.Cut(strings.TrimSpace(hostname), ".")
	return strings.ToUpper(h)
}

// Index maps host keys to computers, across domains.
type Index map[string]Computer

// NewIndex indexes the computers of the snapshots. With duplicate names
// across domains, the most recently active wins.
func NewIndex(snaps []*Snapshot) Index {
	idx := Index{}
	for _, s := range snaps {
		for _, c := range s.Computers {
			if cur, ok := idx[c.Name]; !ok || c.lastSeen().After(cur.lastSeen()) {
				idx[c.Name] = c
			}
		}
	}
	return idx
}

// Report compares a domain with the agents.
type Report struct {
	Domain       string
	CollectedAt  time.Time
	Truncated    bool
	Total        int
	Enabled      int
	WithAgent    int
	WithoutAgent []Computer // active, without an agent
	Stale        []Computer // enabled, unused for StaleDays
}

// Analyze compares a snapshot with the host keys of the agents.
func Analyze(s *Snapshot, agents map[string]bool, now time.Time) Report {
	r := Report{Domain: s.Domain, CollectedAt: s.CollectedAt, Truncated: s.Truncated, Total: len(s.Computers)}
	for _, c := range s.Computers {
		if c.Enabled {
			r.Enabled++
		}
		switch {
		case agents[c.Name]:
			r.WithAgent++
		case c.Active(now):
			r.WithoutAgent = append(r.WithoutAgent, c)
		}
		if c.Stale(now) {
			r.Stale = append(r.Stale, c)
		}
	}
	sort.Slice(r.Stale, func(i, j int) bool { return r.Stale[i].lastSeen().Before(r.Stale[j].lastSeen()) })
	return r
}
