package store

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// WebSession is an operator session of the web console. Data is opaque to
// the store (JSON encoded by the web package).
type WebSession struct {
	ID        string // clear-text id, never stored
	Data      json.RawMessage
	CreatedAt time.Time
	LastSeen  time.Time
	ExpiresAt time.Time
}

func sessionHash(id string) []byte {
	sum := sha256.Sum256([]byte("openrmm/web-session/v1\x00" + id))
	return sum[:]
}

// SessionStore persists web sessions.
type SessionStore interface {
	SaveSession(ctx context.Context, s WebSession) error
	// GetSession returns ErrNotFound for unknown or expired sessions.
	GetSession(ctx context.Context, id string, now time.Time) (WebSession, error)
	DeleteSession(ctx context.Context, id string) error
	DeleteExpiredSessions(ctx context.Context, now time.Time) error
	ListEnrollmentTokens(ctx context.Context, tenantID string) ([]EnrollmentToken, error)
}

func (m *Memory) SaveSession(_ context.Context, s WebSession) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := string(sessionHash(s.ID))
	if old, ok := m.sessions[k]; ok && s.CreatedAt.IsZero() {
		s.CreatedAt = old.CreatedAt
	}
	s.ID = ""
	m.sessions[k] = s
	return nil
}

func (m *Memory) GetSession(_ context.Context, id string, now time.Time) (WebSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[string(sessionHash(id))]
	if !ok || !now.Before(s.ExpiresAt) {
		return WebSession{}, ErrNotFound
	}
	s.ID = id
	return s, nil
}

func (m *Memory) DeleteSession(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, string(sessionHash(id)))
	return nil
}

func (m *Memory) DeleteExpiredSessions(_ context.Context, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, s := range m.sessions {
		if !now.Before(s.ExpiresAt) {
			delete(m.sessions, k)
		}
	}
	return nil
}

func (m *Memory) ListEnrollmentTokens(_ context.Context, tenantID string) ([]EnrollmentToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []EnrollmentToken
	for _, t := range m.tokens {
		if t.TenantID == tenantID {
			out = append(out, t)
		}
	}
	return out, nil
}

func (p *Postgres) SaveSession(ctx context.Context, s WebSession) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO web_sessions (id_hash, data, last_seen, expires_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (id_hash) DO UPDATE SET data = EXCLUDED.data, last_seen = EXCLUDED.last_seen,
		expires_at = EXCLUDED.expires_at`,
		sessionHash(s.ID), string(s.Data), s.LastSeen, s.ExpiresAt)
	return err
}

func (p *Postgres) GetSession(ctx context.Context, id string, now time.Time) (WebSession, error) {
	s := WebSession{ID: id}
	var data string
	err := p.pool.QueryRow(ctx, `SELECT data::text, created_at, last_seen, expires_at FROM web_sessions
		WHERE id_hash = $1 AND expires_at > $2`, sessionHash(id), now).Scan(&data, &s.CreatedAt, &s.LastSeen, &s.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return WebSession{}, ErrNotFound
	}
	s.Data = json.RawMessage(data)
	return s, err
}

func (p *Postgres) DeleteSession(ctx context.Context, id string) error {
	_, err := p.pool.Exec(ctx, `DELETE FROM web_sessions WHERE id_hash = $1`, sessionHash(id))
	return err
}

func (p *Postgres) DeleteExpiredSessions(ctx context.Context, now time.Time) error {
	_, err := p.pool.Exec(ctx, `DELETE FROM web_sessions WHERE expires_at <= $1`, now)
	return err
}

func (p *Postgres) ListEnrollmentTokens(ctx context.Context, tenantID string) ([]EnrollmentToken, error) {
	rows, err := p.pool.Query(ctx, `SELECT id::text, tenant_id::text, description, max_uses, uses, expires_at,
		revoked_at, auto_approve FROM enrollment_tokens WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 200`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EnrollmentToken
	for rows.Next() {
		var t EnrollmentToken
		if err := rows.Scan(&t.ID, &t.TenantID, &t.Description, &t.MaxUses, &t.Uses, &t.ExpiresAt, &t.RevokedAt, &t.AutoApprove); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
