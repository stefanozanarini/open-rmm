package policies

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/open-rmm/internal/agent/executor"
	"github.com/stefanozanarini/open-rmm/internal/ids"
	"github.com/stefanozanarini/open-rmm/internal/policy"
	"github.com/stefanozanarini/open-rmm/internal/signing"
)

type fakeProbe struct {
	services map[string]bool
	family   string
}

func (f fakeProbe) ServiceExists(n string) bool   { return f.services[n] }
func (f fakeProbe) FileExists(string) bool        { return false }
func (f fakeProbe) RegistryKeyExists(string) bool { return false }
func (f fakeProbe) OSFamily() string              { return f.family }

type fakeStarter struct {
	mu   sync.Mutex
	runs []string // policy/rule
}

func (f *fakeStarter) StartPolicy(job *openrmmv1.Job, pr executor.PolicyRun, done func(*openrmmv1.PolicyResult)) {
	f.mu.Lock()
	f.runs = append(f.runs, pr.RuleID)
	f.mu.Unlock()
	go done(&openrmmv1.PolicyResult{RunId: job.GetJobId(), State: openrmmv1.JobUpdate_STATE_SUCCEEDED})
}

func (f *fakeStarter) ran() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.runs...)
}

type fixture struct {
	signer *signing.Signer
	keys   *signing.Keyring
	tenant string
	dir    string
}

func newFixture(t *testing.T) *fixture {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, _ := signing.NewSigner(priv)
	k := signing.NewKeyring()
	k.Add(pub, signing.DomainJob, signing.DomainPolicy)
	return &fixture{signer: s, keys: k, tenant: ids.NewUUID(), dir: t.TempDir()}
}

func (f *fixture) pol(id string, version int64, applies string, rules ...policy.Rule) *policy.Policy {
	return &policy.Policy{ID: id, TenantID: f.tenant, Name: "p", Version: version, AppliesTo: applies, Rules: rules}
}

func rule(id string, when *policy.Condition) policy.Rule {
	return policy.Rule{ID: id, Module: "sysinfo", ModuleVersion: "1.0.0", ModuleSHA256: hex.EncodeToString(make([]byte, 32)),
		Action: "info", EverySeconds: 60, When: when}
}

func (f *fixture) seal(t *testing.T, p *policy.Policy) *openrmmv1.SignedEnvelope {
	raw, err := p.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	return &openrmmv1.SignedEnvelope{KeyId: f.signer.KeyID(), Payload: raw, Signature: f.signer.Sign(signing.DomainPolicy, raw)}
}

func (f *fixture) manager(t *testing.T, probe Probe, st *fakeStarter) *Manager {
	m, err := New(f.keys, f.tenant, f.dir, probe, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func set(envs ...*openrmmv1.SignedEnvelope) *openrmmv1.PolicySet {
	return &openrmmv1.PolicySet{Policies: envs}
}

func TestApplyVerifiesAndRefusesRollback(t *testing.T) {
	FirstRunSpread = time.Millisecond
	f := newFixture(t)
	st := &fakeStarter{}
	m := f.manager(t, fakeProbe{family: "client"}, st)
	id := ids.NewUUID()

	m.Apply(set(f.seal(t, f.pol(id, 2, policy.AppliesAll, rule("v2", nil)))))
	if m.Count() != 1 {
		t.Fatal("valid policy not applied")
	}
	// An older version, validly signed, must not replace the newer one.
	m.Apply(set(f.seal(t, f.pol(id, 1, policy.AppliesAll, rule("v1", nil)))))
	time.Sleep(5 * time.Millisecond)
	m.RunDue()
	waitRuns(t, st, 1)
	if got := st.ran(); got[0] != "v2" {
		t.Fatalf("ran %v: rolled back to an older version", got)
	}

	// Another tenant's policy, a bad signature and an unknown key are ignored.
	other := f.pol(ids.NewUUID(), 1, policy.AppliesAll, rule("x", nil))
	other.TenantID = ids.NewUUID()
	bad := f.seal(t, f.pol(ids.NewUUID(), 1, policy.AppliesAll, rule("y", nil)))
	bad.Signature[0] ^= 1
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	stranger, _ := signing.NewSigner(priv)
	raw, _ := f.pol(ids.NewUUID(), 1, policy.AppliesAll, rule("z", nil)).Canonical()
	foreign := &openrmmv1.SignedEnvelope{KeyId: stranger.KeyID(), Payload: raw, Signature: stranger.Sign(signing.DomainPolicy, raw)}
	// A job signature is not a policy signature.
	jobSig := &openrmmv1.SignedEnvelope{KeyId: f.signer.KeyID(), Payload: raw, Signature: f.signer.Sign(signing.DomainJob, raw)}
	m.Apply(set(f.seal(t, f.pol(id, 2, policy.AppliesAll, rule("v2", nil))), f.seal(t, other), bad, foreign, jobSig))
	if m.Count() != 1 {
		t.Fatalf("%d policies active, want 1", m.Count())
	}

	// Removal: a set without the policy removes it.
	m.Apply(set())
	if m.Count() != 0 {
		t.Fatal("policy not removed")
	}
}

func TestConditionsAndFamily(t *testing.T) {
	FirstRunSpread = time.Millisecond
	f := newFixture(t)
	st := &fakeStarter{}
	m := f.manager(t, fakeProbe{family: "server", services: map[string]bool{"ds_agent": true}}, st)
	m.Apply(set(
		f.seal(t, f.pol(ids.NewUUID(), 1, policy.AppliesAll,
			rule("trend-swp", &policy.Condition{ServiceExists: "ds_agent"}),
			rule("trend-sep", &policy.Condition{ServiceExists: "TMBMServer"}),
			rule("not-sep", &policy.Condition{Not: &policy.Condition{ServiceExists: "TMBMServer"}}),
			rule("any", &policy.Condition{Any: []policy.Condition{{ServiceExists: "nope"}, {OSFamily: "server"}}}),
		)),
		f.seal(t, f.pol(ids.NewUUID(), 1, policy.AppliesClients, rule("clients-only", nil))),
	))
	time.Sleep(5 * time.Millisecond)
	m.RunDue()
	waitRuns(t, st, 3)
	time.Sleep(50 * time.Millisecond)
	got := map[string]bool{}
	for _, r := range st.ran() {
		got[r] = true
	}
	if !got["trend-swp"] || !got["not-sep"] || !got["any"] || got["trend-sep"] || got["clients-only"] || len(got) != 3 {
		t.Fatalf("ran %v", st.ran())
	}
}

func TestStatePersistsAcrossRestarts(t *testing.T) {
	FirstRunSpread = time.Millisecond
	f := newFixture(t)
	st := &fakeStarter{}
	m := f.manager(t, fakeProbe{family: "client"}, st)
	id := ids.NewUUID()
	m.Apply(set(f.seal(t, f.pol(id, 3, policy.AppliesAll, rule("r", nil)))))
	time.Sleep(5 * time.Millisecond)
	m.RunDue()
	waitRuns(t, st, 1)
	time.Sleep(50 * time.Millisecond)

	// After a restart: the policy is still there (offline), it is not run
	// again before its interval, and older versions stay refused.
	st2 := &fakeStarter{}
	m2 := f.manager(t, fakeProbe{family: "client"}, st2)
	if m2.Count() != 1 {
		t.Fatal("policy lost on restart")
	}
	m2.RunDue()
	time.Sleep(50 * time.Millisecond)
	if len(st2.ran()) != 0 {
		t.Fatal("rule re-run immediately after restart")
	}
	m2.Apply(set(f.seal(t, f.pol(id, 2, policy.AppliesAll, rule("old", nil)))))
	if m2.Count() != 1 {
		t.Fatal("current policy dropped by an older version")
	}
}

func waitRuns(t *testing.T, st *fakeStarter, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for len(st.ran()) < n {
		if time.Now().After(deadline) {
			t.Fatalf("runs = %v, want %d", st.ran(), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestWindowDefersRules(t *testing.T) {
	FirstRunSpread = time.Millisecond
	f := newFixture(t)
	st := &fakeStarter{}
	m := f.manager(t, fakeProbe{}, st)
	now := time.Date(2026, 10, 19, 10, 0, 0, 0, time.Local) // Monday 10:00
	m.now = func() time.Time { return now }
	r := rule("night", nil)
	r.Window = &policy.Window{Start: "22:00", End: "05:00"}
	m.Apply(set(f.seal(t, f.pol(ids.NewUUID(), 1, policy.AppliesAll, r))))
	now = now.Add(time.Minute)
	m.RunDue()
	time.Sleep(20 * time.Millisecond)
	if len(st.ran()) != 0 {
		t.Fatal("rule ran outside its window")
	}
	now = time.Date(2026, 10, 19, 22, 30, 0, 0, time.Local)
	m.RunDue()
	waitRuns(t, st, 1)
	time.Sleep(50 * time.Millisecond) // let the completion persist the state
}
