package store

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrStaleReport is returned for a report older than the stored one.
var ErrStaleReport = errors.New("report older than the stored one")

// UpdateStatus is the latest update report of an agent for one source.
type UpdateStatus struct {
	TenantID    string
	AgentID     string
	Source      string // windows | winget
	ScannedAt   time.Time
	Data        []byte // normalized report (internal/updates)
	ManagedBy   string
	Important   int
	Other       int
	OldestDays  int
	Behind      int
	Reboot      bool
	RebootSince *time.Time
	ThirdParty  int
}

// UpdateStore keeps update reports.
type UpdateStore interface {
	PutUpdateStatus(ctx context.Context, s UpdateStatus) error
	// ListUpdateStatus returns the reports of the tenant (agentID "" for all).
	ListUpdateStatus(ctx context.Context, tenantID, agentID string) ([]UpdateStatus, error)
}

// ---- memory ----

func (m *Memory) PutUpdateStatus(_ context.Context, s UpdateStatus) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.agents[agentKey(s.TenantID, s.AgentID)]; !ok {
		return ErrNotFound
	}
	if m.updates == nil {
		m.updates = map[string]UpdateStatus{}
	}
	k := s.TenantID + "/" + s.AgentID + "/" + s.Source
	if cur, ok := m.updates[k]; ok && cur.ScannedAt.After(s.ScannedAt) {
		return ErrStaleReport
	}
	m.updates[k] = s
	return nil
}

func (m *Memory) ListUpdateStatus(_ context.Context, tenantID, agentID string) ([]UpdateStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []UpdateStatus
	for _, s := range m.updates {
		if s.TenantID == tenantID && (agentID == "" || s.AgentID == agentID) {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AgentID+out[i].Source < out[j].AgentID+out[j].Source })
	return out, nil
}

// ---- postgres ----

func (p *Postgres) PutUpdateStatus(ctx context.Context, s UpdateStatus) error {
	err := p.inTenant(ctx, s.TenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO update_status (tenant_id, agent_id, source, scanned_at, data, managed_by,
			important, other, oldest_days, behind, reboot, reboot_since, third_party)
			VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9,$10,$11,$12,$13)
			ON CONFLICT (tenant_id, agent_id, source) DO UPDATE SET scanned_at = EXCLUDED.scanned_at, data = EXCLUDED.data,
			managed_by = EXCLUDED.managed_by, important = EXCLUDED.important, other = EXCLUDED.other,
			oldest_days = EXCLUDED.oldest_days, behind = EXCLUDED.behind, reboot = EXCLUDED.reboot,
			reboot_since = EXCLUDED.reboot_since, third_party = EXCLUDED.third_party
			WHERE update_status.scanned_at <= EXCLUDED.scanned_at`,
			s.TenantID, s.AgentID, s.Source, s.ScannedAt, string(s.Data), s.ManagedBy, s.Important, s.Other,
			s.OldestDays, s.Behind, s.Reboot, s.RebootSince, s.ThirdParty)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrStaleReport
		}
		return nil
	})
	return fkNotFound(err)
}

func (p *Postgres) ListUpdateStatus(ctx context.Context, tenantID, agentID string) ([]UpdateStatus, error) {
	var out []UpdateStatus
	err := p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT agent_id::text, source, scanned_at, data::text, managed_by, important, other,
			oldest_days, behind, reboot, reboot_since, third_party FROM update_status
			WHERE ($1 = '' OR agent_id::text = $1) ORDER BY agent_id, source`, agentID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			s := UpdateStatus{TenantID: tenantID}
			var data string
			if err := rows.Scan(&s.AgentID, &s.Source, &s.ScannedAt, &data, &s.ManagedBy, &s.Important, &s.Other,
				&s.OldestDays, &s.Behind, &s.Reboot, &s.RebootSince, &s.ThirdParty); err != nil {
				return err
			}
			s.Data = []byte(data)
			out = append(out, s)
		}
		return rows.Err()
	})
	return out, err
}
