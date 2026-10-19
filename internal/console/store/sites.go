package store

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ErrSiteExists is returned for a duplicate site name.
var ErrSiteExists = errors.New("a site with this name exists")

// Site groups agents by network.
type Site struct {
	TenantID  string
	ID        string
	Name      string
	Subnets   []string // CIDR
	CreatedAt time.Time
}

// Note is an operator note on an agent.
type Note struct {
	TenantID  string
	ID        string
	AgentID   string
	Body      string
	Author    string
	CreatedAt time.Time
}

// SiteStore keeps sites and notes.
type SiteStore interface {
	PutSite(ctx context.Context, s Site) error // insert or update by id
	DeleteSite(ctx context.Context, tenantID, id string) error
	ListSites(ctx context.Context, tenantID string) ([]Site, error)

	AddNote(ctx context.Context, n Note) error
	ListNotes(ctx context.Context, tenantID, agentID string, limit int) ([]Note, error)
}

// ---- memory ----

func (m *Memory) PutSite(_ context.Context, s Site) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sites == nil {
		m.sites = map[string]Site{}
	}
	for _, cur := range m.sites {
		if cur.TenantID == s.TenantID && cur.Name == s.Name && cur.ID != s.ID {
			return ErrSiteExists
		}
	}
	if old, ok := m.sites[s.TenantID+"/"+s.ID]; ok {
		s.CreatedAt = old.CreatedAt
	} else if s.CreatedAt.IsZero() {
		s.CreatedAt = time.Now()
	}
	m.sites[s.TenantID+"/"+s.ID] = s
	return nil
}

func (m *Memory) DeleteSite(_ context.Context, tenantID, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.sites[tenantID+"/"+id]; !ok {
		return ErrNotFound
	}
	delete(m.sites, tenantID+"/"+id)
	return nil
}

func (m *Memory) ListSites(_ context.Context, tenantID string) ([]Site, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Site
	for _, s := range m.sites {
		if s.TenantID == tenantID {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *Memory) AddNote(_ context.Context, n Note) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.agents[agentKey(n.TenantID, n.AgentID)]; !ok {
		return ErrNotFound
	}
	if n.CreatedAt.IsZero() {
		n.CreatedAt = time.Now()
	}
	m.notes = append(m.notes, n)
	return nil
}

func (m *Memory) ListNotes(_ context.Context, tenantID, agentID string, limit int) ([]Note, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Note
	for i := len(m.notes) - 1; i >= 0 && len(out) < limit; i-- {
		if n := m.notes[i]; n.TenantID == tenantID && n.AgentID == agentID {
			out = append(out, n)
		}
	}
	return out, nil
}

// ---- postgres ----

func (p *Postgres) PutSite(ctx context.Context, s Site) error {
	err := p.inTenant(ctx, s.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO sites (tenant_id, id, name, subnets) VALUES ($1,$2,$3,$4)
			ON CONFLICT (tenant_id, id) DO UPDATE SET name = EXCLUDED.name, subnets = EXCLUDED.subnets`,
			s.TenantID, s.ID, s.Name, nonNil(s.Subnets))
		return err
	})
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return ErrSiteExists
	}
	return err
}

func (p *Postgres) DeleteSite(ctx context.Context, tenantID, id string) error {
	return p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM sites WHERE id = $1`, id)
		if err == nil && tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return err
	})
}

func (p *Postgres) ListSites(ctx context.Context, tenantID string) ([]Site, error) {
	var out []Site
	err := p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id::text, name, subnets, created_at FROM sites ORDER BY name`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			s := Site{TenantID: tenantID}
			if err := rows.Scan(&s.ID, &s.Name, &s.Subnets, &s.CreatedAt); err != nil {
				return err
			}
			out = append(out, s)
		}
		return rows.Err()
	})
	return out, err
}

func (p *Postgres) AddNote(ctx context.Context, n Note) error {
	err := p.inTenant(ctx, n.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO agent_notes (tenant_id, id, agent_id, body, author) VALUES ($1,$2,$3,$4,$5)`,
			n.TenantID, n.ID, n.AgentID, n.Body, n.Author)
		return err
	})
	return fkNotFound(err)
}

func (p *Postgres) ListNotes(ctx context.Context, tenantID, agentID string, limit int) ([]Note, error) {
	var out []Note
	err := p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id::text, body, author, created_at FROM agent_notes WHERE agent_id = $1
			ORDER BY created_at DESC LIMIT $2`, agentID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			n := Note{TenantID: tenantID, AgentID: agentID}
			if err := rows.Scan(&n.ID, &n.Body, &n.Author, &n.CreatedAt); err != nil {
				return err
			}
			out = append(out, n)
		}
		return rows.Err()
	})
	return out, err
}
