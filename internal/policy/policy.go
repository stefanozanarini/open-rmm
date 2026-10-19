// Package policy defines policies: signed documents that tell an agent which
// module actions to run periodically, and under which local conditions.
//
// A policy is approved once per version (operator MFA, signed by the signer)
// and then runs on its own, also offline. The agent core only evaluates the
// declarative conditions below; it knows nothing about the products they
// detect, so plugins can be activated automatically without growing the core.
package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/ids"
	"github.com/stefanozanarini/open-rmm/internal/modules"
)

// Target OS families.
const (
	AppliesAll     = "all"
	AppliesClients = "clients"
	AppliesServers = "servers"
)

const (
	MinEvery  = time.Minute
	MaxEvery  = 7 * 24 * time.Hour
	maxRules  = 100
	maxParams = 64 << 10
	maxDepth  = 4
)

var (
	nameRe   = regexp.MustCompile(`^[\pL\pN][\pL\pN ._-]{0,79}$`)
	ruleIDRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,40}$`)
	actionRe = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,40}$`)
)

// Policy is the signed document.
type Policy struct {
	ID        string `json:"id"`
	TenantID  string `json:"tenant_id"`
	Name      string `json:"name"`
	Version   int64  `json:"version"`
	AppliesTo string `json:"applies_to"`
	Rules     []Rule `json:"rules"`
}

// Rule schedules one module action.
type Rule struct {
	ID            string          `json:"id"`
	Module        string          `json:"module"`
	ModuleVersion string          `json:"module_version"`
	ModuleSHA256  string          `json:"module_sha256"` // hex, pins the signed manifest
	Action        string          `json:"action"`
	Params        json.RawMessage `json:"params,omitempty"`
	EverySeconds  int64           `json:"every_seconds"`
	When          *Condition      `json:"when,omitempty"`
	// Window, when set, lets the rule run only inside it.
	Window *Window `json:"window,omitempty"`
}

// Every returns the rule interval.
func (r Rule) Every() time.Duration { return time.Duration(r.EverySeconds) * time.Second }

// Condition is a declarative test evaluated on the endpoint. Exactly one
// field is set.
type Condition struct {
	ServiceExists     string      `json:"service_exists,omitempty"`
	FileExists        string      `json:"file_exists,omitempty"`
	RegistryKeyExists string      `json:"registry_key_exists,omitempty"` // HKLM\..., Windows only
	OSFamily          string      `json:"os_family,omitempty"`           // client | server
	All               []Condition `json:"all,omitempty"`
	Any               []Condition `json:"any,omitempty"`
	Not               *Condition  `json:"not,omitempty"`
}

// Validate checks a policy.
func (p *Policy) Validate() error {
	if !ids.IsUUID(p.ID) || !ids.IsUUID(p.TenantID) {
		return errors.New("policy and tenant ids must be UUIDs")
	}
	if !nameRe.MatchString(p.Name) {
		return errors.New("invalid policy name")
	}
	if p.Version < 1 {
		return errors.New("version must be at least 1")
	}
	switch p.AppliesTo {
	case AppliesAll, AppliesClients, AppliesServers:
	default:
		return fmt.Errorf("applies_to must be %s, %s or %s", AppliesAll, AppliesClients, AppliesServers)
	}
	if len(p.Rules) > maxRules {
		return fmt.Errorf("at most %d rules", maxRules)
	}
	seen := map[string]bool{}
	for i, r := range p.Rules {
		if !ruleIDRe.MatchString(r.ID) || seen[r.ID] {
			return fmt.Errorf("rule %d: invalid or duplicate id %q", i+1, r.ID)
		}
		seen[r.ID] = true
		if !modules.ValidID(r.Module) || !modules.ValidVersion(r.ModuleVersion) {
			return fmt.Errorf("rule %s: invalid module reference", r.ID)
		}
		if b, err := hex.DecodeString(r.ModuleSHA256); err != nil || len(b) != sha256.Size {
			return fmt.Errorf("rule %s: module_sha256 must be a hex SHA-256", r.ID)
		}
		if !actionRe.MatchString(r.Action) {
			return fmt.Errorf("rule %s: invalid action", r.ID)
		}
		if len(r.Params) > maxParams {
			return fmt.Errorf("rule %s: parameters too large", r.ID)
		}
		if len(r.Params) > 0 {
			var obj map[string]any
			if err := json.Unmarshal(r.Params, &obj); err != nil {
				return fmt.Errorf("rule %s: params must be a JSON object", r.ID)
			}
		}
		if e := r.Every(); e < MinEvery || e > MaxEvery {
			return fmt.Errorf("rule %s: interval must be between %s and %s", r.ID, MinEvery, MaxEvery)
		}
		if r.When != nil {
			if err := r.When.validate(0); err != nil {
				return fmt.Errorf("rule %s: %w", r.ID, err)
			}
		}
		if r.Window != nil {
			if err := r.Window.validate(); err != nil {
				return fmt.Errorf("rule %s: %w", r.ID, err)
			}
		}
	}
	return nil
}

func (c *Condition) validate(depth int) error {
	if depth > maxDepth {
		return errors.New("conditions nested too deeply")
	}
	set := 0
	for _, s := range []string{c.ServiceExists, c.FileExists, c.RegistryKeyExists, c.OSFamily} {
		if s != "" {
			set++
		}
	}
	if len(c.All) > 0 {
		set++
	}
	if len(c.Any) > 0 {
		set++
	}
	if c.Not != nil {
		set++
	}
	if set != 1 {
		return errors.New("each condition must have exactly one test")
	}
	switch {
	case c.ServiceExists != "":
		if len(c.ServiceExists) > 256 || strings.ContainsAny(c.ServiceExists, `/\`) {
			return errors.New("invalid service name")
		}
	case c.FileExists != "":
		if len(c.FileExists) > 260 || strings.Contains(c.FileExists, "..") {
			return errors.New("invalid file path")
		}
	case c.RegistryKeyExists != "":
		if !strings.HasPrefix(strings.ToUpper(c.RegistryKeyExists), `HKLM\`) || len(c.RegistryKeyExists) > 255 {
			return errors.New(`registry keys must start with HKLM\`)
		}
	case c.OSFamily != "":
		if c.OSFamily != "client" && c.OSFamily != "server" {
			return errors.New("os_family must be client or server")
		}
	}
	for _, sub := range append(append([]Condition{}, c.All...), c.Any...) {
		if err := sub.validate(depth + 1); err != nil {
			return err
		}
	}
	if c.Not != nil {
		return c.Not.validate(depth + 1)
	}
	return nil
}

// Canonical returns the bytes that are approved and signed: compact JSON in
// struct order, params re-encoded compactly.
func (p *Policy) Canonical() ([]byte, error) {
	cp := *p
	cp.Rules = make([]Rule, len(p.Rules))
	for i, r := range p.Rules {
		if len(r.Params) > 0 {
			var buf bytes.Buffer
			if err := json.Compact(&buf, r.Params); err != nil {
				return nil, err
			}
			r.Params = buf.Bytes()
			if string(r.Params) == "{}" {
				r.Params = nil
			}
		}
		cp.Rules[i] = r
	}
	return json.Marshal(cp)
}

// Parse decodes and validates a canonical policy document.
func Parse(raw []byte) (*Policy, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	p := &Policy{}
	if err := dec.Decode(p); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	return p, p.Validate()
}

// AuthNonce is the OIDC nonce for the step-up authentication approving the
// exact policy document raw.
func AuthNonce(raw []byte) string {
	sum := sha256.Sum256(append([]byte("openrmm/policy-approval/v1\x00"), raw...))
	return "policy." + base64.RawURLEncoding.EncodeToString(sum[:])
}

// AppliesToFamily reports whether a policy targets an OS family.
func (p *Policy) AppliesToFamily(family string) bool {
	switch p.AppliesTo {
	case AppliesClients:
		return family == "client"
	case AppliesServers:
		return family == "server"
	}
	return true
}
