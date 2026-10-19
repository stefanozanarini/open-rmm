package store

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var (
	// ErrLinkExists is returned for a duplicate link name.
	ErrLinkExists = errors.New("a linked console with this name exists")
	// ErrLinkToken is returned for an unknown, used or expired link token.
	ErrLinkToken = errors.New("link token invalid, expired or already used")
)

// Link statuses.
const (
	LinkPending = "pending"
	LinkActive  = "active"
	LinkRevoked = "revoked"
)

// FederationLink is a customer console linked to this (central) console.
type FederationLink struct {
	ID              string
	TenantID        string // central tenant whose operators use the link
	Name            string
	Status          string
	CertFingerprint string // of the customer console's link certificate
	TokenExpiresAt  *time.Time
	CreatedBy       string
	CreatedAt       time.Time
	EnrolledAt      *time.Time
	LastSeenAt      *time.Time
	Summary         []byte // JSON reported by the customer console
	SummaryAt       *time.Time
}

// Uplink is this (customer) console's link to a central console.
type Uplink struct {
	LinkID             string
	CentralAddr        string // host:port of the central link listener
	CentralFingerprint string // pinned certificate of the central console
	CertPEM, KeyPEM    string // this console's link identity
	Suspended          bool
	CreatedBy          string
	CreatedAt          time.Time
}

// FederationStore keeps both sides of federation links.
type FederationStore interface {
	CreateLink(ctx context.Context, l FederationLink, tokenHash []byte) error
	// EnrollLink binds a pending link to the certificate of the customer
	// console presenting its token, once.
	EnrollLink(ctx context.Context, tokenHash []byte, fingerprint string, now time.Time) (FederationLink, error)
	LinkByFingerprint(ctx context.Context, fingerprint string) (FederationLink, error)
	GetLink(ctx context.Context, tenantID, id string) (FederationLink, error)
	ListLinks(ctx context.Context, tenantID string) ([]FederationLink, error)
	RevokeLink(ctx context.Context, tenantID, id string) error
	// TouchLink records contact, and the summary when not nil.
	TouchLink(ctx context.Context, id string, now time.Time, summary []byte) error

	GetUplink(ctx context.Context) (Uplink, error)
	PutUplink(ctx context.Context, u Uplink) error
	SetUplinkSuspended(ctx context.Context, suspended bool) error
	DeleteUplink(ctx context.Context) error

	// GetConsoleKey returns a named certificate and key of this console;
	// PutConsoleKey stores one unless it exists (then it returns the
	// existing one, so concurrent first starts agree).
	GetConsoleKey(ctx context.Context, name string) (certPEM, keyPEM string, err error)
	PutConsoleKey(ctx context.Context, name, certPEM, keyPEM string) (string, string, error)
}

// ---- memory ----

type memFederation struct {
	links  map[string]FederationLink
	tokens map[string]string // token hash -> link id
	uplink *Uplink
	keys   map[string][2]string
}

func (m *Memory) fed() *memFederation {
	if m.federation == nil {
		m.federation = &memFederation{links: map[string]FederationLink{}, tokens: map[string]string{}, keys: map[string][2]string{}}
	}
	return m.federation
}

func (m *Memory) CreateLink(_ context.Context, l FederationLink, tokenHash []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	f := m.fed()
	for _, cur := range f.links {
		if cur.TenantID == l.TenantID && cur.Name == l.Name {
			return ErrLinkExists
		}
	}
	if l.CreatedAt.IsZero() {
		l.CreatedAt = time.Now()
	}
	l.Status = LinkPending
	f.links[l.ID] = l
	f.tokens[string(tokenHash)] = l.ID
	return nil
}

func (m *Memory) EnrollLink(_ context.Context, tokenHash []byte, fingerprint string, now time.Time) (FederationLink, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f := m.fed()
	id, ok := f.tokens[string(tokenHash)]
	if !ok {
		return FederationLink{}, ErrLinkToken
	}
	l := f.links[id]
	if l.Status != LinkPending || l.TokenExpiresAt == nil || !now.Before(*l.TokenExpiresAt) {
		return FederationLink{}, ErrLinkToken
	}
	for _, cur := range f.links {
		if cur.CertFingerprint == fingerprint {
			return FederationLink{}, ErrLinkToken
		}
	}
	delete(f.tokens, string(tokenHash))
	l.Status, l.CertFingerprint, l.TokenExpiresAt, l.EnrolledAt = LinkActive, fingerprint, nil, &now
	f.links[id] = l
	return l, nil
}

func (m *Memory) LinkByFingerprint(_ context.Context, fingerprint string) (FederationLink, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, l := range m.fed().links {
		if fingerprint != "" && l.CertFingerprint == fingerprint {
			return l, nil
		}
	}
	return FederationLink{}, ErrNotFound
}

func (m *Memory) GetLink(_ context.Context, tenantID, id string) (FederationLink, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	l, ok := m.fed().links[id]
	if !ok || l.TenantID != tenantID {
		return FederationLink{}, ErrNotFound
	}
	return l, nil
}

func (m *Memory) ListLinks(_ context.Context, tenantID string) ([]FederationLink, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []FederationLink
	for _, l := range m.fed().links {
		if l.TenantID == tenantID {
			out = append(out, l)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *Memory) RevokeLink(_ context.Context, tenantID, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	f := m.fed()
	l, ok := f.links[id]
	if !ok || l.TenantID != tenantID {
		return ErrNotFound
	}
	for h, lid := range f.tokens {
		if lid == id {
			delete(f.tokens, h)
		}
	}
	l.Status = LinkRevoked
	f.links[id] = l
	return nil
}

func (m *Memory) TouchLink(_ context.Context, id string, now time.Time, summary []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	f := m.fed()
	l, ok := f.links[id]
	if !ok {
		return ErrNotFound
	}
	l.LastSeenAt = &now
	if summary != nil {
		l.Summary, l.SummaryAt = summary, &now
	}
	f.links[id] = l
	return nil
}

func (m *Memory) GetUplink(context.Context) (Uplink, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u := m.fed().uplink; u != nil {
		return *u, nil
	}
	return Uplink{}, ErrNotFound
}

func (m *Memory) PutUplink(_ context.Context, u Uplink) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u.CreatedAt.IsZero() {
		u.CreatedAt = time.Now()
	}
	m.fed().uplink = &u
	return nil
}

func (m *Memory) SetUplinkSuspended(_ context.Context, suspended bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.fed().uplink
	if u == nil {
		return ErrNotFound
	}
	u.Suspended = suspended
	return nil
}

func (m *Memory) DeleteUplink(context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fed().uplink = nil
	return nil
}

func (m *Memory) GetConsoleKey(_ context.Context, name string) (string, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.fed().keys[name]
	if !ok {
		return "", "", ErrNotFound
	}
	return k[0], k[1], nil
}

func (m *Memory) PutConsoleKey(_ context.Context, name, certPEM, keyPEM string) (string, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f := m.fed()
	if k, ok := f.keys[name]; ok {
		return k[0], k[1], nil
	}
	f.keys[name] = [2]string{certPEM, keyPEM}
	return certPEM, keyPEM, nil
}

// ---- postgres ----

const linkColumns = `id::text, tenant_id::text, name, status, coalesce(cert_fingerprint, ''), token_expires_at,
	created_by, created_at, enrolled_at, last_seen_at, summary, summary_at`

func scanLink(row pgx.Row) (FederationLink, error) {
	var l FederationLink
	err := row.Scan(&l.ID, &l.TenantID, &l.Name, &l.Status, &l.CertFingerprint, &l.TokenExpiresAt,
		&l.CreatedBy, &l.CreatedAt, &l.EnrolledAt, &l.LastSeenAt, &l.Summary, &l.SummaryAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return l, ErrNotFound
	}
	return l, err
}

func (p *Postgres) CreateLink(ctx context.Context, l FederationLink, tokenHash []byte) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO federation_links (id, tenant_id, name, token_hash, token_expires_at, status, created_by)
		VALUES ($1,$2,$3,$4,$5,'pending',$6)`, l.ID, l.TenantID, l.Name, tokenHash, l.TokenExpiresAt, l.CreatedBy)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return ErrLinkExists
	}
	return err
}

func (p *Postgres) EnrollLink(ctx context.Context, tokenHash []byte, fingerprint string, now time.Time) (FederationLink, error) {
	l, err := scanLink(p.pool.QueryRow(ctx, `UPDATE federation_links
		SET status = 'active', cert_fingerprint = $2, token_hash = NULL, token_expires_at = NULL, enrolled_at = $3
		WHERE token_hash = $1 AND status = 'pending' AND token_expires_at > $3
		RETURNING `+linkColumns, tokenHash, fingerprint, now))
	var pgErr *pgconn.PgError
	if errors.Is(err, ErrNotFound) || (errors.As(err, &pgErr) && pgErr.Code == "23505") {
		return FederationLink{}, ErrLinkToken
	}
	return l, err
}

func (p *Postgres) LinkByFingerprint(ctx context.Context, fingerprint string) (FederationLink, error) {
	return scanLink(p.pool.QueryRow(ctx, `SELECT `+linkColumns+` FROM federation_links WHERE cert_fingerprint = $1`, fingerprint))
}

func (p *Postgres) GetLink(ctx context.Context, tenantID, id string) (FederationLink, error) {
	return scanLink(p.pool.QueryRow(ctx, `SELECT `+linkColumns+` FROM federation_links WHERE tenant_id = $1 AND id = $2`, tenantID, id))
}

func (p *Postgres) ListLinks(ctx context.Context, tenantID string) ([]FederationLink, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+linkColumns+` FROM federation_links WHERE tenant_id = $1 ORDER BY name`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FederationLink
	for rows.Next() {
		l, err := scanLink(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

func (p *Postgres) RevokeLink(ctx context.Context, tenantID, id string) error {
	tag, err := p.pool.Exec(ctx, `UPDATE federation_links SET status = 'revoked', token_hash = NULL
		WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (p *Postgres) TouchLink(ctx context.Context, id string, now time.Time, summary []byte) error {
	tag, err := p.pool.Exec(ctx, `UPDATE federation_links SET last_seen_at = $2,
		summary = coalesce($3, summary), summary_at = CASE WHEN $3::jsonb IS NULL THEN summary_at ELSE $2 END
		WHERE id = $1`, id, now, summary)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (p *Postgres) GetUplink(ctx context.Context) (Uplink, error) {
	var u Uplink
	err := p.pool.QueryRow(ctx, `SELECT link_id::text, central_addr, central_fingerprint, cert_pem, key_pem, suspended,
		created_by, created_at FROM federation_uplink`).Scan(&u.LinkID, &u.CentralAddr, &u.CentralFingerprint,
		&u.CertPEM, &u.KeyPEM, &u.Suspended, &u.CreatedBy, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return u, ErrNotFound
	}
	return u, err
}

func (p *Postgres) PutUplink(ctx context.Context, u Uplink) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO federation_uplink
		(link_id, central_addr, central_fingerprint, cert_pem, key_pem, suspended, created_by) VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (singleton) DO UPDATE SET link_id = EXCLUDED.link_id, central_addr = EXCLUDED.central_addr,
			central_fingerprint = EXCLUDED.central_fingerprint, cert_pem = EXCLUDED.cert_pem, key_pem = EXCLUDED.key_pem,
			suspended = EXCLUDED.suspended, created_by = EXCLUDED.created_by, created_at = now()`,
		u.LinkID, u.CentralAddr, u.CentralFingerprint, u.CertPEM, u.KeyPEM, u.Suspended, u.CreatedBy)
	return err
}

func (p *Postgres) SetUplinkSuspended(ctx context.Context, suspended bool) error {
	tag, err := p.pool.Exec(ctx, `UPDATE federation_uplink SET suspended = $1`, suspended)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (p *Postgres) DeleteUplink(ctx context.Context) error {
	_, err := p.pool.Exec(ctx, `DELETE FROM federation_uplink`)
	return err
}

func (p *Postgres) GetConsoleKey(ctx context.Context, name string) (string, string, error) {
	var c, k string
	err := p.pool.QueryRow(ctx, `SELECT cert_pem, key_pem FROM console_keys WHERE name = $1`, name).Scan(&c, &k)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", ErrNotFound
	}
	return c, k, err
}

func (p *Postgres) PutConsoleKey(ctx context.Context, name, certPEM, keyPEM string) (string, string, error) {
	if _, err := p.pool.Exec(ctx, `INSERT INTO console_keys (name, cert_pem, key_pem) VALUES ($1,$2,$3)
		ON CONFLICT (name) DO NOTHING`, name, certPEM, keyPEM); err != nil {
		return "", "", err
	}
	return p.GetConsoleKey(ctx, name)
}
