package store

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var ErrReleaseExists = errors.New("release already published")

// Rings.
const (
	RingPilot = "pilot"
	RingBroad = "broad"
)

// ValidRing reports whether r is a known ring.
func ValidRing(r string) bool { return r == RingPilot || r == RingBroad }

// Release is a published, signed agent release.
type Release struct {
	Version     string
	Platform    string
	KeyID       string
	Manifest    []byte
	Signature   []byte
	Notes       string
	PublishedAt time.Time
	PublishedBy string
	Files       map[string][]byte // only in PutRelease
}

// ReleaseTarget is the version a ring of a tenant should run on a platform.
type ReleaseTarget struct {
	TenantID  string
	Ring      string
	Platform  string
	Version   string
	UpdatedAt time.Time
	UpdatedBy string
}

// AgentUpdate is the last update status reported by an agent.
type AgentUpdate struct {
	State   string
	Version string
	Error   string
	At      time.Time
}

// ReleaseStore manages agent releases and their rollout.
type ReleaseStore interface {
	PutRelease(ctx context.Context, r Release) error
	GetRelease(ctx context.Context, version, platform string) (Release, error)
	GetReleaseFile(ctx context.Context, version, platform, name string) ([]byte, error)
	ListReleases(ctx context.Context) ([]Release, error)
	// SetReleaseTarget wakes the tenant's sessions so the offer goes out.
	SetReleaseTarget(ctx context.Context, t ReleaseTarget) error
	GetReleaseTarget(ctx context.Context, tenantID, ring, platform string) (ReleaseTarget, error)
	ListReleaseTargets(ctx context.Context, tenantID string) ([]ReleaseTarget, error)
	SetAgentRing(ctx context.Context, tenantID, agentID, ring string) error
	SetAgentUpdate(ctx context.Context, tenantID, agentID string, u AgentUpdate) error
}

// TenantWakeKey wakes every session of a tenant.
func TenantWakeKey(tenantID string) string { return tenantID + "/*" }

// ---- memory ----

func relKey(v, p string) string { return v + "@" + p }

func (m *Memory) PutRelease(_ context.Context, r Release) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := relKey(r.Version, r.Platform)
	if _, ok := m.releases[k]; ok {
		return ErrReleaseExists
	}
	if r.PublishedAt.IsZero() {
		r.PublishedAt = time.Now()
	}
	m.releases[k] = r
	return nil
}

func (m *Memory) GetRelease(_ context.Context, version, platform string) (Release, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.releases[relKey(version, platform)]
	if !ok {
		return Release{}, ErrNotFound
	}
	r.Files = nil
	return r, nil
}

func (m *Memory) GetReleaseFile(_ context.Context, version, platform, name string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.releases[relKey(version, platform)]
	if !ok {
		return nil, ErrNotFound
	}
	d, ok := r.Files[name]
	if !ok {
		return nil, ErrNotFound
	}
	return d, nil
}

func (m *Memory) ListReleases(_ context.Context) ([]Release, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Release
	for _, r := range m.releases {
		r.Files = nil
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PublishedAt.After(out[j].PublishedAt) })
	return out, nil
}

func (m *Memory) SetReleaseTarget(_ context.Context, t ReleaseTarget) error {
	m.mu.Lock()
	if _, ok := m.releases[relKey(t.Version, t.Platform)]; !ok {
		m.mu.Unlock()
		return ErrNotFound
	}
	t.UpdatedAt = time.Now()
	m.targets[t.TenantID+"/"+t.Ring+"/"+t.Platform] = t
	listeners := append([]func(string){}, m.listeners...)
	m.mu.Unlock()
	for _, fn := range listeners {
		fn(TenantWakeKey(t.TenantID))
	}
	return nil
}

func (m *Memory) GetReleaseTarget(_ context.Context, tenantID, ring, platform string) (ReleaseTarget, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.targets[tenantID+"/"+ring+"/"+platform]
	if !ok {
		return ReleaseTarget{}, ErrNotFound
	}
	return t, nil
}

func (m *Memory) ListReleaseTargets(_ context.Context, tenantID string) ([]ReleaseTarget, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []ReleaseTarget
	for _, t := range m.targets {
		if t.TenantID == tenantID {
			out = append(out, t)
		}
	}
	return out, nil
}

func (m *Memory) SetAgentRing(_ context.Context, tenantID, agentID, ring string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := agentKey(tenantID, agentID)
	a, ok := m.agents[k]
	if !ok {
		return ErrNotFound
	}
	a.UpdateRing = ring
	m.agents[k] = a
	return nil
}

func (m *Memory) SetAgentUpdate(_ context.Context, tenantID, agentID string, u AgentUpdate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := agentKey(tenantID, agentID)
	a, ok := m.agents[k]
	if !ok {
		return ErrNotFound
	}
	a.Update = u
	m.agents[k] = a
	return nil
}

// ---- postgres ----

func (p *Postgres) PutRelease(ctx context.Context, r Release) error {
	err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO agent_releases (version, platform, key_id, manifest, signature, notes, published_by)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`, r.Version, r.Platform, r.KeyID, r.Manifest, r.Signature, r.Notes, r.PublishedBy); err != nil {
			return err
		}
		for name, data := range r.Files {
			if _, err := tx.Exec(ctx, `INSERT INTO agent_release_files (version, platform, name, data) VALUES ($1,$2,$3,$4)`,
				r.Version, r.Platform, name, data); err != nil {
				return err
			}
		}
		return nil
	})
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return ErrReleaseExists
	}
	return err
}

func (p *Postgres) GetRelease(ctx context.Context, version, platform string) (Release, error) {
	var r Release
	err := p.pool.QueryRow(ctx, `SELECT version, platform, key_id, manifest, signature, notes, published_at, published_by
		FROM agent_releases WHERE version = $1 AND platform = $2`, version, platform).
		Scan(&r.Version, &r.Platform, &r.KeyID, &r.Manifest, &r.Signature, &r.Notes, &r.PublishedAt, &r.PublishedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return Release{}, ErrNotFound
	}
	return r, err
}

func (p *Postgres) GetReleaseFile(ctx context.Context, version, platform, name string) ([]byte, error) {
	var d []byte
	err := p.pool.QueryRow(ctx, `SELECT data FROM agent_release_files WHERE version = $1 AND platform = $2 AND name = $3`,
		version, platform, name).Scan(&d)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return d, err
}

func (p *Postgres) ListReleases(ctx context.Context) ([]Release, error) {
	rows, err := p.pool.Query(ctx, `SELECT version, platform, key_id, manifest, signature, notes, published_at, published_by
		FROM agent_releases ORDER BY published_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Release
	for rows.Next() {
		var r Release
		if err := rows.Scan(&r.Version, &r.Platform, &r.KeyID, &r.Manifest, &r.Signature, &r.Notes, &r.PublishedAt, &r.PublishedBy); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (p *Postgres) SetReleaseTarget(ctx context.Context, t ReleaseTarget) error {
	err := p.inTenant(ctx, t.TenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO release_targets (tenant_id, ring, platform, version, updated_by)
			VALUES ($1,$2,$3,$4,$5)
			ON CONFLICT (tenant_id, ring, platform) DO UPDATE SET version = EXCLUDED.version,
			updated_by = EXCLUDED.updated_by, updated_at = now()`, t.TenantID, t.Ring, t.Platform, t.Version, t.UpdatedBy); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `SELECT pg_notify($1, $2)`, jobsChannel, TenantWakeKey(t.TenantID))
		return err
	})
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23503" {
		return ErrNotFound
	}
	return err
}

func (p *Postgres) GetReleaseTarget(ctx context.Context, tenantID, ring, platform string) (ReleaseTarget, error) {
	var t ReleaseTarget
	err := p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT tenant_id::text, ring, platform, version, updated_at, updated_by FROM release_targets
			WHERE ring = $1 AND platform = $2`, ring, platform).Scan(&t.TenantID, &t.Ring, &t.Platform, &t.Version, &t.UpdatedAt, &t.UpdatedBy)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ReleaseTarget{}, ErrNotFound
	}
	return t, err
}

func (p *Postgres) ListReleaseTargets(ctx context.Context, tenantID string) ([]ReleaseTarget, error) {
	var out []ReleaseTarget
	err := p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT tenant_id::text, ring, platform, version, updated_at, updated_by FROM release_targets
			ORDER BY platform, ring`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var t ReleaseTarget
			if err := rows.Scan(&t.TenantID, &t.Ring, &t.Platform, &t.Version, &t.UpdatedAt, &t.UpdatedBy); err != nil {
				return err
			}
			out = append(out, t)
		}
		return rows.Err()
	})
	return out, err
}

func (p *Postgres) SetAgentRing(ctx context.Context, tenantID, agentID, ring string) error {
	return p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE agents SET update_ring = $2 WHERE id = $1`, agentID, ring)
		if err == nil && tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return err
	})
}

func (p *Postgres) SetAgentUpdate(ctx context.Context, tenantID, agentID string, u AgentUpdate) error {
	return p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE agents SET update_state = $2, update_version = $3, update_error = $4, update_at = $5
			WHERE id = $1`, agentID, u.State, u.Version, u.Error, u.At)
		return err
	})
}
