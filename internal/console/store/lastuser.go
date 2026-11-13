package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// Sources of the last user seen.
const (
	LastUserInventory = "inventory"
	LastUserLogon     = "logon"
)

// LastUser is the last user seen on an agent, kept while nobody is logged
// on or the computer is offline.
type LastUser struct {
	User   string
	SeenAt time.Time
	Source string // inventory | logon
}

// LastUserStore keeps the last user of each agent.
type LastUserStore interface {
	// SetLastUser records u unless a later observation is stored.
	SetLastUser(ctx context.Context, tenantID, agentID string, u LastUser) error
	LastUsers(ctx context.Context, tenantID string) (map[string]LastUser, error)
}

// ---- memory ----

func (m *Memory) SetLastUser(_ context.Context, tenantID, agentID string, u LastUser) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.agents[agentKey(tenantID, agentID)]; !ok {
		return ErrNotFound
	}
	if m.lastUsers == nil {
		m.lastUsers = map[string]LastUser{}
	}
	k := agentKey(tenantID, agentID)
	if cur, ok := m.lastUsers[k]; ok && cur.SeenAt.After(u.SeenAt) {
		return nil
	}
	m.lastUsers[k] = u
	return nil
}

func (m *Memory) LastUsers(_ context.Context, tenantID string) (map[string]LastUser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]LastUser{}
	for _, a := range m.agents {
		if a.TenantID != tenantID {
			continue
		}
		if u, ok := m.lastUsers[agentKey(tenantID, a.ID)]; ok {
			out[a.ID] = u
		}
	}
	return out, nil
}

// ---- postgres ----

func (p *Postgres) SetLastUser(ctx context.Context, tenantID, agentID string, u LastUser) error {
	err := p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO agent_last_user (tenant_id, agent_id, username, seen_at, source) VALUES ($1,$2,$3,$4,$5)
			ON CONFLICT (tenant_id, agent_id) DO UPDATE SET username = EXCLUDED.username, seen_at = EXCLUDED.seen_at, source = EXCLUDED.source
			WHERE agent_last_user.seen_at <= EXCLUDED.seen_at`, tenantID, agentID, u.User, u.SeenAt, u.Source)
		return err
	})
	return fkNotFound(err)
}

func (p *Postgres) LastUsers(ctx context.Context, tenantID string) (map[string]LastUser, error) {
	out := map[string]LastUser{}
	err := p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT agent_id::text, username, seen_at, source FROM agent_last_user`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			var u LastUser
			if err := rows.Scan(&id, &u.User, &u.SeenAt, &u.Source); err != nil {
				return err
			}
			out[id] = u
		}
		return rows.Err()
	})
	return out, err
}
