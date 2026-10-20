package store

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
)

// Installer is a signed agent MSI built for this console.
type Installer struct {
	TenantID  string
	ID        string
	Version   string
	SHA256    string
	Size      int64
	TokenID   string // enrollment token preset in the MSI
	Signer    string // subject of the signing certificate
	CreatedBy string
	CreatedAt time.Time
}

// InstallerStore keeps the built installers.
type InstallerStore interface {
	AddInstaller(ctx context.Context, i Installer) error
	ListInstallers(ctx context.Context, tenantID string) ([]Installer, error)
	GetInstaller(ctx context.Context, tenantID, id string) (Installer, error)
}

// ---- memory ----

func (m *Memory) AddInstaller(_ context.Context, i Installer) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if i.CreatedAt.IsZero() {
		i.CreatedAt = time.Now()
	}
	m.installers = append(m.installers, i)
	return nil
}

func (m *Memory) ListInstallers(_ context.Context, tenantID string) ([]Installer, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Installer
	for _, i := range m.installers {
		if i.TenantID == tenantID {
			out = append(out, i)
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].CreatedAt.After(out[b].CreatedAt) })
	return out, nil
}

func (m *Memory) GetInstaller(_ context.Context, tenantID, id string) (Installer, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, i := range m.installers {
		if i.TenantID == tenantID && i.ID == id {
			return i, nil
		}
	}
	return Installer{}, ErrNotFound
}

// ---- postgres ----

func (p *Postgres) AddInstaller(ctx context.Context, i Installer) error {
	return p.inTenant(ctx, i.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO agent_installers (tenant_id, id, version, sha256, size, token_id, signer, created_by)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, i.TenantID, i.ID, i.Version, i.SHA256, i.Size, i.TokenID, i.Signer, i.CreatedBy)
		return err
	})
}

const installerColumns = `id::text, version, sha256, size, token_id::text, signer, created_by, created_at`

func (p *Postgres) ListInstallers(ctx context.Context, tenantID string) ([]Installer, error) {
	var out []Installer
	err := p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+installerColumns+` FROM agent_installers ORDER BY created_at DESC`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			i := Installer{TenantID: tenantID}
			if err := rows.Scan(&i.ID, &i.Version, &i.SHA256, &i.Size, &i.TokenID, &i.Signer, &i.CreatedBy, &i.CreatedAt); err != nil {
				return err
			}
			out = append(out, i)
		}
		return rows.Err()
	})
	return out, err
}

func (p *Postgres) GetInstaller(ctx context.Context, tenantID, id string) (Installer, error) {
	i := Installer{TenantID: tenantID}
	err := p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT `+installerColumns+` FROM agent_installers WHERE id = $1`, id).
			Scan(&i.ID, &i.Version, &i.SHA256, &i.Size, &i.TokenID, &i.Signer, &i.CreatedBy, &i.CreatedAt)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return i, ErrNotFound
	}
	return i, err
}
