package store

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var ErrPolicyVersion = errors.New("policy version already exists or is not the next one")

// PolicyVersion is one stored version of a policy.
type PolicyVersion struct {
	TenantID  string
	ID        string
	Version   int64
	Name      string
	AppliesTo string
	Document  []byte
	Envelope  []byte
	Deleted   bool
	CreatedBy string
	CreatedAt time.Time
}

// PolicyResult is the latest result of a rule on an agent.
type PolicyResult struct {
	TenantID      string
	AgentID       string
	PolicyID      string
	RuleID        string
	PolicyVersion int64
	RunID         string
	State         JobState
	Result        []byte
	Error         string
	StartedAt     time.Time
	FinishedAt    time.Time
}

// PolicyStore manages policies.
type PolicyStore interface {
	// AddPolicyVersion stores the next version of a policy (version 1 for a
	// new one) and wakes the tenant's sessions.
	AddPolicyVersion(ctx context.Context, v PolicyVersion) error
	// CurrentPolicies returns the latest non-deleted version of each policy.
	CurrentPolicies(ctx context.Context, tenantID string) ([]PolicyVersion, error)
	GetPolicy(ctx context.Context, tenantID, id string) (PolicyVersion, error)
	PutPolicyResult(ctx context.Context, r PolicyResult) error
	ListPolicyResults(ctx context.Context, tenantID, agentID string) ([]PolicyResult, error)
}

func latest(versions []PolicyVersion) map[string]PolicyVersion {
	out := map[string]PolicyVersion{}
	for _, v := range versions {
		if cur, ok := out[v.ID]; !ok || v.Version > cur.Version {
			out[v.ID] = v
		}
	}
	return out
}

// ---- memory ----

func (m *Memory) AddPolicyVersion(_ context.Context, v PolicyVersion) error {
	m.mu.Lock()
	var cur int64
	for _, p := range m.policies {
		if p.TenantID == v.TenantID && p.ID == v.ID && p.Version > cur {
			cur = p.Version
		}
	}
	if v.Version != cur+1 {
		m.mu.Unlock()
		return ErrPolicyVersion
	}
	if v.CreatedAt.IsZero() {
		v.CreatedAt = time.Now()
	}
	m.policies = append(m.policies, v)
	listeners := append([]func(string){}, m.listeners...)
	m.mu.Unlock()
	for _, fn := range listeners {
		fn(TenantWakeKey(v.TenantID))
	}
	return nil
}

func (m *Memory) CurrentPolicies(_ context.Context, tenantID string) ([]PolicyVersion, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var mine []PolicyVersion
	for _, p := range m.policies {
		if p.TenantID == tenantID {
			mine = append(mine, p)
		}
	}
	var out []PolicyVersion
	for _, p := range latest(mine) {
		if !p.Deleted {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *Memory) GetPolicy(ctx context.Context, tenantID, id string) (PolicyVersion, error) {
	cur, _ := m.CurrentPolicies(ctx, tenantID)
	for _, p := range cur {
		if p.ID == id {
			return p, nil
		}
	}
	return PolicyVersion{}, ErrNotFound
}

func (m *Memory) PutPolicyResult(_ context.Context, r PolicyResult) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.agents[agentKey(r.TenantID, r.AgentID)]; !ok {
		return ErrNotFound
	}
	m.results[r.TenantID+"/"+r.AgentID+"/"+r.PolicyID+"/"+r.RuleID] = r
	return nil
}

func (m *Memory) ListPolicyResults(_ context.Context, tenantID, agentID string) ([]PolicyResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []PolicyResult
	for _, r := range m.results {
		if r.TenantID == tenantID && r.AgentID == agentID {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PolicyID+out[i].RuleID < out[j].PolicyID+out[j].RuleID })
	return out, nil
}

// ---- postgres ----

func (p *Postgres) AddPolicyVersion(ctx context.Context, v PolicyVersion) error {
	err := p.inTenant(ctx, v.TenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "policy:"+v.ID); err != nil {
			return err
		}
		var cur int64
		if err := tx.QueryRow(ctx, `SELECT coalesce(max(version), 0) FROM policies WHERE id = $1`, v.ID).Scan(&cur); err != nil {
			return err
		}
		if v.Version != cur+1 {
			return ErrPolicyVersion
		}
		if _, err := tx.Exec(ctx, `INSERT INTO policies (tenant_id, id, version, name, applies_to, document, envelope, deleted, created_by)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, v.TenantID, v.ID, v.Version, v.Name, v.AppliesTo,
			nilIfEmpty(v.Document), nilIfEmpty(v.Envelope), v.Deleted, v.CreatedBy); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `SELECT pg_notify($1, $2)`, jobsChannel, TenantWakeKey(v.TenantID))
		return err
	})
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return ErrPolicyVersion
	}
	return err
}

func nilIfEmpty(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return b
}

func (p *Postgres) CurrentPolicies(ctx context.Context, tenantID string) ([]PolicyVersion, error) {
	var out []PolicyVersion
	err := p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT DISTINCT ON (id) tenant_id::text, id::text, version, name, applies_to,
			coalesce(document, ''), coalesce(envelope, ''), deleted, created_by, created_at
			FROM policies ORDER BY id, version DESC`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var v PolicyVersion
			if err := rows.Scan(&v.TenantID, &v.ID, &v.Version, &v.Name, &v.AppliesTo, &v.Document, &v.Envelope,
				&v.Deleted, &v.CreatedBy, &v.CreatedAt); err != nil {
				return err
			}
			if !v.Deleted {
				out = append(out, v)
			}
		}
		return rows.Err()
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, err
}

func (p *Postgres) GetPolicy(ctx context.Context, tenantID, id string) (PolicyVersion, error) {
	cur, err := p.CurrentPolicies(ctx, tenantID)
	if err != nil {
		return PolicyVersion{}, err
	}
	for _, v := range cur {
		if v.ID == id {
			return v, nil
		}
	}
	return PolicyVersion{}, ErrNotFound
}

func (p *Postgres) PutPolicyResult(ctx context.Context, r PolicyResult) error {
	err := p.inTenant(ctx, r.TenantID, func(tx pgx.Tx) error {
		var result *string
		if len(r.Result) > 0 {
			s := string(r.Result)
			result = &s
		}
		_, err := tx.Exec(ctx, `INSERT INTO policy_results (tenant_id, agent_id, policy_id, rule_id, policy_version,
			run_id, state, result, error, started_at, finished_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10,$11)
			ON CONFLICT (tenant_id, agent_id, policy_id, rule_id) DO UPDATE SET policy_version = EXCLUDED.policy_version,
			run_id = EXCLUDED.run_id, state = EXCLUDED.state, result = EXCLUDED.result, error = EXCLUDED.error,
			started_at = EXCLUDED.started_at, finished_at = EXCLUDED.finished_at
			WHERE policy_results.finished_at <= EXCLUDED.finished_at`,
			r.TenantID, r.AgentID, r.PolicyID, r.RuleID, r.PolicyVersion, r.RunID, string(r.State), result, r.Error,
			r.StartedAt, r.FinishedAt)
		return err
	})
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23503" {
		return ErrNotFound
	}
	return err
}

func (p *Postgres) ListPolicyResults(ctx context.Context, tenantID, agentID string) ([]PolicyResult, error) {
	var out []PolicyResult
	err := p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT tenant_id::text, agent_id::text, policy_id::text, rule_id, policy_version,
			run_id::text, state, coalesce(result::text, ''), error, started_at, finished_at
			FROM policy_results WHERE agent_id = $1 ORDER BY policy_id, rule_id`, agentID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r PolicyResult
			var state, result string
			if err := rows.Scan(&r.TenantID, &r.AgentID, &r.PolicyID, &r.RuleID, &r.PolicyVersion, &r.RunID, &state,
				&result, &r.Error, &r.StartedAt, &r.FinishedAt); err != nil {
				return err
			}
			r.State = JobState(state)
			if result != "" {
				r.Result = []byte(result)
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}
