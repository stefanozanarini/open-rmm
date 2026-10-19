package store

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/console/audit"
)

// Memory is an in-memory Store for tests and local experiments.
type Memory struct {
	mu      sync.Mutex
	tenants map[string]Tenant
	tokens  map[string]EnrollmentToken // by hex(token hash)
	agents  map[string]Agent           // by tenant/agent
	audit   map[string][]audit.Event
	modules map[string]Module // by id@version
	jobs    map[string]Job    // by tenant/job

	listeners   []func(string)
	sessions    map[string]WebSession // by session hash
	releases    map[string]Release    // by version@platform
	targets     map[string]ReleaseTarget
	policies    []PolicyVersion
	results     map[string]PolicyResult
	inventories map[string]*memInventory
	security    *memSecurity
}

func NewMemory() *Memory {
	return &Memory{
		tenants: map[string]Tenant{},
		tokens:  map[string]EnrollmentToken{},
		agents:  map[string]Agent{},
		audit:   map[string][]audit.Event{},
		modules: map[string]Module{},
		jobs:    map[string]Job{},

		sessions:    map[string]WebSession{},
		releases:    map[string]Release{},
		targets:     map[string]ReleaseTarget{},
		results:     map[string]PolicyResult{},
		inventories: map[string]*memInventory{},
	}
}

func agentKey(t, a string) string { return t + "/" + a }

func (m *Memory) CreateTenant(_ context.Context, t Tenant) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.tenants[t.ID]; ok {
		return fmt.Errorf("tenant %s exists", t.ID)
	}
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now()
	}
	m.tenants[t.ID] = t
	return nil
}

func (m *Memory) GetTenant(_ context.Context, id string) (Tenant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tenants[id]
	if !ok {
		return Tenant{}, ErrNotFound
	}
	return t, nil
}

func (m *Memory) CreateEnrollmentToken(_ context.Context, t EnrollmentToken, tokenHash []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.tenants[t.TenantID]; !ok {
		return ErrNotFound
	}
	m.tokens[hex.EncodeToString(tokenHash)] = t
	return nil
}

func (m *Memory) RevokeEnrollmentToken(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, t := range m.tokens {
		if t.ID == id {
			now := time.Now()
			t.RevokedAt = &now
			m.tokens[k] = t
			return nil
		}
	}
	return ErrNotFound
}

func (m *Memory) ConsumeEnrollmentToken(_ context.Context, tokenHash []byte, now time.Time) (EnrollmentToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := hex.EncodeToString(tokenHash)
	t, ok := m.tokens[k]
	if !ok || t.RevokedAt != nil || !now.Before(t.ExpiresAt) || t.Uses >= t.MaxUses {
		return EnrollmentToken{}, ErrTokenInvalid
	}
	t.Uses++
	m.tokens[k] = t
	return t, nil
}

func (m *Memory) CreateAgent(_ context.Context, a Agent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if a.UpdateRing == "" {
		a.UpdateRing = RingBroad
	}
	k := agentKey(a.TenantID, a.ID)
	if _, ok := m.agents[k]; ok {
		return fmt.Errorf("agent %s exists", a.ID)
	}
	m.agents[k] = a
	return nil
}

func (m *Memory) GetAgent(_ context.Context, tenantID, agentID string) (Agent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.agents[agentKey(tenantID, agentID)]
	if !ok {
		return Agent{}, ErrNotFound
	}
	return a, nil
}

func (m *Memory) ListAgents(_ context.Context, tenantID string) ([]Agent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Agent
	for _, a := range m.agents {
		if a.TenantID == tenantID {
			out = append(out, a)
		}
	}
	return out, nil
}

func (m *Memory) UpdateAgentSeen(_ context.Context, tenantID, agentID string, host *HostInfo, seen time.Time, ip *netip.Addr) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := agentKey(tenantID, agentID)
	a, ok := m.agents[k]
	if !ok {
		return ErrNotFound
	}
	if host != nil {
		a.Host = *host
	}
	a.LastSeenAt = &seen
	a.LastSeenIP = ip
	m.agents[k] = a
	return nil
}

func (m *Memory) SetAgentStatus(_ context.Context, tenantID, agentID string, s AgentStatus) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := agentKey(tenantID, agentID)
	a, ok := m.agents[k]
	if !ok {
		return ErrNotFound
	}
	a.Status = s
	m.agents[k] = a
	return nil
}

func (m *Memory) ApproveAgent(_ context.Context, tenantID, agentID, by string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := agentKey(tenantID, agentID)
	a, ok := m.agents[k]
	if !ok {
		return ErrNotFound
	}
	if a.Status != AgentPending {
		return ErrNotPending
	}
	a.Status, a.ApprovedAt, a.ApprovedBy = AgentActive, &at, by
	m.agents[k] = a
	listeners := append([]func(string){}, m.listeners...)
	go func() {
		for _, fn := range listeners {
			fn(WakeKey(tenantID, agentID))
		}
	}()
	return nil
}

func (m *Memory) RotateAgentCert(_ context.Context, tenantID, agentID, used, newFP string, notAfter time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := agentKey(tenantID, agentID)
	a, ok := m.agents[k]
	if !ok || a.Status == AgentRevoked {
		return ErrNotFound
	}
	if used != a.CertFingerprint && (a.PrevCertFingerprint == "" || used != a.PrevCertFingerprint) {
		return ErrCertMismatch
	}
	a.PrevCertFingerprint, a.CertFingerprint, a.CertNotAfter = used, newFP, notAfter
	m.agents[k] = a
	return nil
}

func (m *Memory) ForgetPrevCert(_ context.Context, tenantID, agentID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := agentKey(tenantID, agentID)
	a, ok := m.agents[k]
	if !ok {
		return ErrNotFound
	}
	a.PrevCertFingerprint = ""
	m.agents[k] = a
	return nil
}

func (m *Memory) AppendAudit(_ context.Context, e audit.Event) (audit.Event, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	chain := m.audit[e.TenantID]
	prev := audit.GenesisHash
	if len(chain) > 0 {
		prev = chain[len(chain)-1].Hash
	}
	e, err := prepareAudit(e, int64(len(chain))+1, prev)
	if err != nil {
		return e, err
	}
	m.audit[e.TenantID] = append(chain, e)
	return e, nil
}

func (m *Memory) ListAudit(_ context.Context, tenantID string) ([]audit.Event, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]audit.Event(nil), m.audit[tenantID]...), nil
}
