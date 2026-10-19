// Package policies applies the signed policies received from the console:
// it verifies them, keeps them on disk so they also run offline, evaluates
// their conditions and schedules their module actions.
package policies

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/open-rmm/internal/agent/executor"
	"github.com/stefanozanarini/open-rmm/internal/agent/secfile"
	"github.com/stefanozanarini/open-rmm/internal/ids"
	"github.com/stefanozanarini/open-rmm/internal/policy"
	"github.com/stefanozanarini/open-rmm/internal/signing"
)

const (
	stateFile    = "policies.json"
	maxPolicies  = 50
	conditionTTL = 5 * time.Minute // how stale a condition result may be
)

// Scheduling knobs; variables only so tests can shorten them.
var (
	// Tick is how often the scheduler looks for due rules.
	Tick = 15 * time.Second
	// FirstRunSpread bounds the random delay before a rule's first run, so
	// a fleet receiving a new policy does not run it all at once.
	FirstRunSpread = 2 * time.Minute
)

// Starter runs one policy rule (the executor in production).
type Starter interface {
	StartPolicy(job *openrmmv1.Job, pr executor.PolicyRun, done func(*openrmmv1.PolicyResult))
}

type active struct {
	env *openrmmv1.SignedEnvelope
	pol *policy.Policy
}

// state is persisted in <data>/policies.json.
type state struct {
	// Envelopes of the current set (serialized SignedEnvelope).
	Set [][]byte `json:"set"`
	// MaxVersion per policy id: older versions are never accepted again.
	MaxVersion map[string]int64 `json:"max_version"`
	// LastRun per "policy/rule".
	LastRun map[string]time.Time `json:"last_run"`
}

type condCache struct {
	ok bool
	at time.Time
}

// Manager applies policies for one agent identity.
type Manager struct {
	keys     *signing.Keyring
	tenantID string
	dataDir  string
	probe    Probe
	start    Starter
	log      *slog.Logger
	now      func() time.Time

	mu       sync.Mutex
	st       state
	active   map[string]active // by policy id
	running  map[string]bool   // by policy/rule
	conds    map[string]condCache
	firstDue map[string]time.Time // jittered first run of never-run rules
}

// New loads the persisted policies (verifying them again).
func New(keys *signing.Keyring, tenantID, dataDir string, probe Probe, start Starter, log *slog.Logger) (*Manager, error) {
	m := &Manager{keys: keys, tenantID: tenantID, dataDir: dataDir, probe: probe, start: start, log: log,
		now: time.Now, active: map[string]active{}, running: map[string]bool{},
		conds: map[string]condCache{}, firstDue: map[string]time.Time{},
		st: state{MaxVersion: map[string]int64{}, LastRun: map[string]time.Time{}}}
	raw, err := os.ReadFile(filepath.Join(dataDir, stateFile)) // #nosec G304 -- agent data dir
	switch {
	case errors.Is(err, os.ErrNotExist):
		return m, nil
	case err != nil:
		return nil, err
	}
	var st state
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, fmt.Errorf("policy state corrupt: %w", err)
	}
	if st.MaxVersion != nil {
		m.st.MaxVersion = st.MaxVersion
	}
	if st.LastRun != nil {
		m.st.LastRun = st.LastRun
	}
	for _, b := range st.Set {
		env := &openrmmv1.SignedEnvelope{}
		if proto.Unmarshal(b, env) != nil {
			continue
		}
		if p, err := m.verify(env); err == nil {
			m.active[p.ID] = active{env: env, pol: p}
		} else {
			log.Warn("stored policy no longer valid, dropped", "err", err)
		}
	}
	m.st.Set = m.envelopes()
	m.seedFirstRuns()
	return m, nil
}

// seedFirstRuns schedules the first run of rules that never ran, when the
// policy arrives (not at the first scheduler pass).
func (m *Manager) seedFirstRuns() {
	now := m.now()
	for _, a := range m.active {
		for _, r := range a.pol.Rules {
			m.due(a.pol.ID+"/"+r.ID, r, now)
		}
	}
}

func (m *Manager) verify(env *openrmmv1.SignedEnvelope) (*policy.Policy, error) {
	if err := m.keys.Verify(signing.DomainPolicy, env.GetKeyId(), env.GetPayload(), env.GetSignature()); err != nil {
		return nil, err
	}
	p, err := policy.Parse(env.GetPayload())
	if err != nil {
		return nil, err
	}
	if p.TenantID != m.tenantID {
		return nil, errors.New("policy for another tenant")
	}
	return p, nil
}

// Apply replaces the current set with the one received from the console.
// Invalid policies are ignored; a policy older than one already seen keeps
// the newer version (a compromised console cannot roll a policy back).
func (m *Manager) Apply(set *openrmmv1.PolicySet) {
	m.mu.Lock()
	defer m.mu.Unlock()
	next := map[string]active{}
	for i, env := range set.GetPolicies() {
		if i >= maxPolicies {
			m.log.Warn("too many policies, ignoring the rest")
			break
		}
		p, err := m.verify(env)
		if err != nil {
			m.log.Warn("policy rejected", "err", err)
			continue
		}
		if p.Version < m.st.MaxVersion[p.ID] {
			m.log.Warn("older policy version refused", "policy", p.ID, "version", p.Version, "known", m.st.MaxVersion[p.ID])
			if cur, ok := m.active[p.ID]; ok {
				next[p.ID] = cur
			}
			continue
		}
		m.st.MaxVersion[p.ID] = p.Version
		next[p.ID] = active{env: env, pol: p}
	}
	for id, a := range next {
		if old, ok := m.active[id]; !ok || old.pol.Version != a.pol.Version {
			m.log.Info("policy applied", "policy", a.pol.Name, "version", a.pol.Version, "rules", len(a.pol.Rules))
		}
	}
	for id, old := range m.active {
		if _, ok := next[id]; !ok {
			m.log.Info("policy removed", "policy", old.pol.Name)
		}
	}
	m.active = next
	m.conds = map[string]condCache{}
	m.seedFirstRuns()
	m.st.Set = m.envelopes()
	m.persist()
}

func (m *Manager) envelopes() [][]byte {
	keys := make([]string, 0, len(m.active))
	for id := range m.active {
		keys = append(keys, id)
	}
	sort.Strings(keys)
	var out [][]byte
	for _, id := range keys {
		if b, err := proto.Marshal(m.active[id].env); err == nil {
			out = append(out, b)
		}
	}
	return out
}

func (m *Manager) persist() {
	raw, err := json.Marshal(m.st)
	if err == nil {
		err = secfile.WriteFile(filepath.Join(m.dataDir, stateFile), raw)
	}
	if err != nil {
		m.log.Error("persist policy state", "err", err)
	}
}

// Run schedules the rules until ctx ends.
func (m *Manager) Run(ctx context.Context) {
	t := time.NewTicker(Tick)
	defer t.Stop()
	for {
		m.RunDue()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// RunDue starts every rule that is due and whose conditions hold.
func (m *Manager) RunDue() {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	family := m.probe.OSFamily()
	for _, a := range m.active {
		if !a.pol.AppliesToFamily(family) {
			continue
		}
		for _, r := range a.pol.Rules {
			key := a.pol.ID + "/" + r.ID
			if m.running[key] || now.Before(m.due(key, r, now)) {
				continue
			}
			if !m.condition(key, r, now) {
				continue
			}
			m.launch(a.pol, r, key)
		}
	}
}

// due returns when a rule should next run. A rule that never ran starts
// after a random delay, so a fleet does not run everything at once.
func (m *Manager) due(key string, r policy.Rule, now time.Time) time.Time {
	if last, ok := m.st.LastRun[key]; ok {
		return last.Add(r.Every())
	}
	if d, ok := m.firstDue[key]; ok {
		return d
	}
	spread := max(min(r.Every(), FirstRunSpread), time.Millisecond)
	d := now.Add(time.Duration(rand.Int64N(int64(spread)))) // #nosec G404 -- scheduling jitter
	m.firstDue[key] = d
	return d
}

func (m *Manager) condition(key string, r policy.Rule, now time.Time) bool {
	if c, ok := m.conds[key]; ok && now.Sub(c.at) < conditionTTL {
		return c.ok
	}
	ok := Eval(r.When, m.probe)
	m.conds[key] = condCache{ok: ok, at: now}
	return ok
}

func (m *Manager) launch(p *policy.Policy, r policy.Rule, key string) {
	sha, _ := hex.DecodeString(r.ModuleSHA256)
	params := []byte(r.Params)
	if len(params) == 0 {
		params = []byte("{}")
	}
	job := &openrmmv1.Job{JobId: ids.NewUUID(), Module: r.Module, ModuleVersion: r.ModuleVersion,
		ModuleSha256: sha, Action: r.Action, ParamsJson: params}
	m.running[key] = true
	started := m.now()
	m.start.StartPolicy(job, executor.PolicyRun{PolicyID: p.ID, PolicyVersion: p.Version, RuleID: r.ID},
		func(res *openrmmv1.PolicyResult) {
			m.mu.Lock()
			defer m.mu.Unlock()
			delete(m.running, key)
			m.st.LastRun[key] = started
			m.persist()
			if res.GetState() != openrmmv1.JobUpdate_STATE_SUCCEEDED {
				m.log.Warn("policy rule failed", "policy", p.Name, "rule", r.ID, "state", res.GetState().String(), "error", res.GetError())
			}
		})
}

// Count returns the number of active policies (tests, health).
func (m *Manager) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.active)
}
