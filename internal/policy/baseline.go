package policy

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"time"
)

// Automatic collection: the policy the console keeps by itself in every
// tenant, so that approved agents report inventory, updates, protection and
// sign-ins without anyone writing rules. It only schedules the read-only
// collection actions below, at fixed intervals and without parameters; the
// signer signs it without an operator's approval only when it matches this
// list exactly (CheckBaseline). What runs is still the module version
// pinned by hash and signed with the module release key.

// BaselineName is the name of the automatic collection policy.
const BaselineName = "Raccolta automatica"

// BaselineRule is one scheduled collection.
type BaselineRule struct {
	Module, Action string
	Every          time.Duration
	When           *Condition
}

// BaselineRules lists the collections, in rule order.
var BaselineRules = []BaselineRule{
	{"inventory", "collect", 24 * time.Hour, nil},
	{"winupdate", "scan", 24 * time.Hour, nil},
	{"winget", "scan", 24 * time.Hour, nil},
	{"firmware", "scan", 24 * time.Hour, nil},
	{"protection-status", "status", time.Hour, nil},
	{"accesslog", "collect", 5 * time.Minute, nil},
	{"trendmicro", "status", 15 * time.Minute, &Condition{Any: []Condition{
		{ServiceExists: "ntrtscan"}, {ServiceExists: "ds_agent"}, {ServiceExists: "EndpointBasecamp"}}}},
	{"adinventory", "collect", 24 * time.Hour, &Condition{ServiceExists: "NTDS"}},
}

// ModuleRef is a published module version, pinned by its manifest hash.
type ModuleRef struct {
	Version string
	SHA256  string // hex
}

// BaselineID is the id of a tenant's automatic collection policy.
func BaselineID(tenant string) string {
	b := sha256.Sum256([]byte("openrmm/baseline/v1\x00" + tenant))
	b[6] = b[6]&0x0f | 0x80 // UUID version 8 (custom), RFC 9562 variant
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// Baseline builds the automatic collection policy of tenant with the given
// published modules (by id); collections whose module is not published are
// left out. It returns nil when no collection is possible.
func Baseline(tenant string, version int64, mods map[string]ModuleRef) *Policy {
	p := &Policy{ID: BaselineID(tenant), TenantID: tenant, Name: BaselineName, Version: version, AppliesTo: AppliesAll}
	for _, b := range BaselineRules {
		ref, ok := mods[b.Module]
		if !ok {
			continue
		}
		p.Rules = append(p.Rules, Rule{ID: b.Module, Module: b.Module, ModuleVersion: ref.Version, ModuleSHA256: ref.SHA256,
			Action: b.Action, EverySeconds: int64(b.Every / time.Second), When: b.When})
	}
	if len(p.Rules) == 0 {
		return nil
	}
	return p
}

// SameRules tells whether two policies schedule the same module versions,
// ignoring their version numbers.
func SameRules(a, b *Policy) bool {
	return a != nil && b != nil && a.AppliesTo == b.AppliesTo && reflect.DeepEqual(a.Rules, b.Rules)
}

// CheckBaseline verifies that p is an automatic collection policy: its id,
// name and target, and only collections of BaselineRules, each at most
// once, exactly as listed (no parameters, no window).
func CheckBaseline(p *Policy) error {
	if p.ID != BaselineID(p.TenantID) || p.Name != BaselineName || p.AppliesTo != AppliesAll {
		return errors.New("not the automatic collection policy")
	}
	byModule := map[string]BaselineRule{}
	for _, b := range BaselineRules {
		byModule[b.Module] = b
	}
	seen := map[string]bool{}
	for _, r := range p.Rules {
		b, ok := byModule[r.Module]
		if !ok || seen[r.Module] {
			return fmt.Errorf("rule %s is not an automatic collection", r.ID)
		}
		seen[r.Module] = true
		if r.ID != b.Module || r.Action != b.Action || r.Every() != b.Every || len(r.Params) != 0 || r.Window != nil ||
			!reflect.DeepEqual(r.When, b.When) {
			return fmt.Errorf("rule %s differs from the automatic collection", r.ID)
		}
	}
	return nil
}
