package store

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrStaleADReport is returned for a report older than the stored one.
var ErrStaleADReport = errors.New("older Active Directory report")

// ADDomain is the computer list of a domain (adinv.Snapshot as JSON).
type ADDomain struct {
	TenantID    string
	Domain      string
	AgentID     string // endpoint that reported it
	CollectedAt time.Time
	Data        []byte
}

// ADStore keeps Active Directory reports.
type ADStore interface {
	PutADDomain(ctx context.Context, d ADDomain) error
	ListADDomains(ctx context.Context, tenantID string) ([]ADDomain, error)
}

// ---- memory ----

func (m *Memory) PutADDomain(_ context.Context, d ADDomain) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.agents[agentKey(d.TenantID, d.AgentID)]; !ok {
		return ErrNotFound
	}
	if m.adDomains == nil {
		m.adDomains = map[string]ADDomain{}
	}
	k := d.TenantID + "/" + d.Domain
	if cur, ok := m.adDomains[k]; ok && !d.CollectedAt.After(cur.CollectedAt) {
		return ErrStaleADReport
	}
	m.adDomains[k] = d
	return nil
}

func (m *Memory) ListADDomains(_ context.Context, tenantID string) ([]ADDomain, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []ADDomain
	for _, d := range m.adDomains {
		if d.TenantID == tenantID {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out, nil
}

// ---- postgres ----

func (p *Postgres) PutADDomain(ctx context.Context, d ADDomain) error {
	err := p.inTenant(ctx, d.TenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO ad_domains (tenant_id, domain, agent_id, collected_at, data) VALUES ($1,$2,$3,$4,$5)
			ON CONFLICT (tenant_id, domain) DO UPDATE SET agent_id = EXCLUDED.agent_id, collected_at = EXCLUDED.collected_at,
				data = EXCLUDED.data, updated_at = now()
			WHERE ad_domains.collected_at < EXCLUDED.collected_at`,
			d.TenantID, d.Domain, d.AgentID, d.CollectedAt, d.Data)
		if err == nil && tag.RowsAffected() == 0 {
			return ErrStaleADReport
		}
		return err
	})
	return fkNotFound(err)
}

func (p *Postgres) ListADDomains(ctx context.Context, tenantID string) ([]ADDomain, error) {
	var out []ADDomain
	err := p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT domain, agent_id::text, collected_at, data FROM ad_domains ORDER BY domain`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			d := ADDomain{TenantID: tenantID}
			if err := rows.Scan(&d.Domain, &d.AgentID, &d.CollectedAt, &d.Data); err != nil {
				return err
			}
			out = append(out, d)
		}
		return rows.Err()
	})
	return out, err
}
