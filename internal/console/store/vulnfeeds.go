package store

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// VulnFeed is a downloaded vulnerability source, as a compact extract.
type VulnFeed struct {
	Key       string // e.g. kev, msrc/2026-Oct
	Version   string // the source's own revision, to fetch again only when it changes
	Data      []byte
	FetchedAt time.Time
}

// VulnFeedStore keeps the vulnerability sources.
type VulnFeedStore interface {
	PutVulnFeed(ctx context.Context, f VulnFeed) error
	GetVulnFeed(ctx context.Context, key string) (VulnFeed, error)
	// ListVulnFeeds returns the feeds whose key starts with prefix.
	ListVulnFeeds(ctx context.Context, prefix string) ([]VulnFeed, error)
}

// ---- memory ----

func (m *Memory) PutVulnFeed(_ context.Context, f VulnFeed) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.vulnFeeds == nil {
		m.vulnFeeds = map[string]VulnFeed{}
	}
	if f.FetchedAt.IsZero() {
		f.FetchedAt = time.Now()
	}
	m.vulnFeeds[f.Key] = f
	return nil
}

func (m *Memory) GetVulnFeed(_ context.Context, key string) (VulnFeed, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.vulnFeeds[key]
	if !ok {
		return VulnFeed{}, ErrNotFound
	}
	return f, nil
}

func (m *Memory) ListVulnFeeds(_ context.Context, prefix string) ([]VulnFeed, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []VulnFeed
	for k, f := range m.vulnFeeds {
		if strings.HasPrefix(k, prefix) {
			out = append(out, f)
		}
	}
	return out, nil
}

// ---- postgres ----

func (p *Postgres) PutVulnFeed(ctx context.Context, f VulnFeed) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO vuln_feeds (key, version, data, fetched_at) VALUES ($1,$2,$3,now())
		ON CONFLICT (key) DO UPDATE SET version = EXCLUDED.version, data = EXCLUDED.data, fetched_at = now()`, f.Key, f.Version, f.Data)
	return err
}

func (p *Postgres) GetVulnFeed(ctx context.Context, key string) (VulnFeed, error) {
	f := VulnFeed{Key: key}
	err := p.pool.QueryRow(ctx, `SELECT version, data, fetched_at FROM vuln_feeds WHERE key = $1`, key).Scan(&f.Version, &f.Data, &f.FetchedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return f, ErrNotFound
	}
	return f, err
}

func (p *Postgres) ListVulnFeeds(ctx context.Context, prefix string) ([]VulnFeed, error) {
	rows, err := p.pool.Query(ctx, `SELECT key, version, data, fetched_at FROM vuln_feeds WHERE starts_with(key, $1) ORDER BY key`, prefix)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VulnFeed
	for rows.Next() {
		var f VulnFeed
		if err := rows.Scan(&f.Key, &f.Version, &f.Data, &f.FetchedAt); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}
