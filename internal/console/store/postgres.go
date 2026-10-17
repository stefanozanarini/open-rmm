package store

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/stefanozanarini/open-rmm/internal/console/audit"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Postgres is the production Store.
type Postgres struct {
	pool *pgxpool.Pool
}

// OpenPostgres connects to the database.
func OpenPostgres(ctx context.Context, url string) (*Postgres, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	// Superusers and BYPASSRLS roles ignore row-level security, which would
	// silently disable tenant isolation.
	var bypass bool
	if err := pool.QueryRow(ctx, `SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&bypass); err != nil {
		pool.Close()
		return nil, err
	}
	if bypass {
		pool.Close()
		return nil, errors.New("refusing to run as a PostgreSQL superuser or BYPASSRLS role: create a dedicated role (see docs)")
	}
	return &Postgres{pool: pool}, nil
}

func (p *Postgres) Close() { p.pool.Close() }

// Migrate applies pending migrations in lexical order, each in its own
// transaction, serialized by an advisory lock.
func (p *Postgres) Migrate(ctx context.Context) error {
	names, err := fs.Glob(migrationsFS, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)
	conn, err := p.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock(727274)`); err != nil {
		return err
	}
	defer conn.Exec(context.Background(), `SELECT pg_advisory_unlock(727274)`) //nolint:errcheck
	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	for _, name := range names {
		base := strings.TrimPrefix(name, "migrations/")
		var exists bool
		if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE name = $1)`, base).Scan(&exists); err != nil {
			return err
		}
		if exists {
			continue
		}
		sql, err := migrationsFS.ReadFile(name)
		if err != nil {
			return err
		}
		err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, string(sql)); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO schema_migrations (name) VALUES ($1)`, base)
			return err
		})
		if err != nil {
			return fmt.Errorf("migration %s: %w", base, err)
		}
	}
	return nil
}

// inTenant runs fn in a transaction scoped to tenantID for row-level security.
func (p *Postgres) inTenant(ctx context.Context, tenantID string, fn func(pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('openrmm.tenant_id', $1, true)`, tenantID); err != nil {
			return err
		}
		return fn(tx)
	})
}

func (p *Postgres) CreateTenant(ctx context.Context, t Tenant) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1, $2)`, t.ID, t.Name)
	return err
}

func (p *Postgres) GetTenant(ctx context.Context, id string) (Tenant, error) {
	var t Tenant
	err := p.pool.QueryRow(ctx, `SELECT id::text, name, created_at FROM tenants WHERE id = $1`, id).
		Scan(&t.ID, &t.Name, &t.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Tenant{}, ErrNotFound
	}
	return t, err
}

func (p *Postgres) CreateEnrollmentToken(ctx context.Context, t EnrollmentToken, tokenHash []byte) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO enrollment_tokens
		(id, tenant_id, token_hash, description, max_uses, expires_at, auto_approve)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		t.ID, t.TenantID, tokenHash, t.Description, t.MaxUses, t.ExpiresAt, t.AutoApprove)
	return err
}

func (p *Postgres) RevokeEnrollmentToken(ctx context.Context, id string) error {
	tag, err := p.pool.Exec(ctx, `UPDATE enrollment_tokens SET revoked_at = now()
		WHERE id = $1 AND revoked_at IS NULL`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (p *Postgres) ConsumeEnrollmentToken(ctx context.Context, tokenHash []byte, now time.Time) (EnrollmentToken, error) {
	var t EnrollmentToken
	err := p.pool.QueryRow(ctx, `UPDATE enrollment_tokens SET uses = uses + 1
		WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > $2 AND uses < max_uses
		RETURNING id::text, tenant_id::text, description, max_uses, uses, expires_at, auto_approve`,
		tokenHash, now).Scan(&t.ID, &t.TenantID, &t.Description, &t.MaxUses, &t.Uses, &t.ExpiresAt, &t.AutoApprove)
	if errors.Is(err, pgx.ErrNoRows) {
		return EnrollmentToken{}, ErrTokenInvalid
	}
	return t, err
}

func (p *Postgres) CreateAgent(ctx context.Context, a Agent) error {
	return p.inTenant(ctx, a.TenantID, func(tx pgx.Tx) error {
		var tokenID *string
		if a.EnrolledTokenID != "" {
			tokenID = &a.EnrolledTokenID
		}
		_, err := tx.Exec(ctx, `INSERT INTO agents
			(tenant_id, id, status, hostname, os, os_version, arch, agent_version, machine_id,
			 cert_fingerprint, cert_not_after, enrolled_token_id, approved_at, approved_by)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
			a.TenantID, a.ID, string(a.Status), a.Host.Hostname, a.Host.OS, a.Host.OSVersion, a.Host.Arch,
			a.Host.AgentVersion, a.Host.MachineID, a.CertFingerprint, a.CertNotAfter, tokenID, a.ApprovedAt, a.ApprovedBy)
		return err
	})
}

const agentColumns = `tenant_id::text, id::text, status, hostname, os, os_version, arch, agent_version,
	machine_id, cert_fingerprint, cert_not_after, enrolled_at, coalesce(enrolled_token_id::text, ''),
	last_seen_at, last_seen_ip, coalesce(prev_cert_fingerprint, ''), approved_at, approved_by`

func scanAgent(row pgx.Row) (Agent, error) {
	var a Agent
	var status string
	var ip *netip.Addr
	err := row.Scan(&a.TenantID, &a.ID, &status, &a.Host.Hostname, &a.Host.OS, &a.Host.OSVersion,
		&a.Host.Arch, &a.Host.AgentVersion, &a.Host.MachineID, &a.CertFingerprint, &a.CertNotAfter,
		&a.EnrolledAt, &a.EnrolledTokenID, &a.LastSeenAt, &ip, &a.PrevCertFingerprint, &a.ApprovedAt, &a.ApprovedBy)
	a.Status = AgentStatus(status)
	a.LastSeenIP = ip
	return a, err
}

func (p *Postgres) GetAgent(ctx context.Context, tenantID, agentID string) (Agent, error) {
	var a Agent
	err := p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		a, err = scanAgent(tx.QueryRow(ctx, `SELECT `+agentColumns+` FROM agents WHERE id = $1`, agentID))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Agent{}, ErrNotFound
	}
	return a, err
}

func (p *Postgres) ListAgents(ctx context.Context, tenantID string) ([]Agent, error) {
	var out []Agent
	err := p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+agentColumns+` FROM agents ORDER BY hostname, id`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			a, err := scanAgent(rows)
			if err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}

func (p *Postgres) UpdateAgentSeen(ctx context.Context, tenantID, agentID string, host *HostInfo, seen time.Time, ip *netip.Addr) error {
	return p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		var n int64
		if host != nil {
			tag, e := tx.Exec(ctx, `UPDATE agents SET last_seen_at = $2, last_seen_ip = $3,
				hostname = $4, os = $5, os_version = $6, arch = $7, agent_version = $8, machine_id = $9
				WHERE id = $1`, agentID, seen, ip, host.Hostname, host.OS, host.OSVersion, host.Arch,
				host.AgentVersion, host.MachineID)
			err, n = e, tag.RowsAffected()
		} else {
			tag, e := tx.Exec(ctx, `UPDATE agents SET last_seen_at = $2, last_seen_ip = $3 WHERE id = $1`,
				agentID, seen, ip)
			err, n = e, tag.RowsAffected()
		}
		if err == nil && n == 0 {
			return ErrNotFound
		}
		return err
	})
}

func (p *Postgres) SetAgentStatus(ctx context.Context, tenantID, agentID string, s AgentStatus) error {
	return p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE agents SET status = $2 WHERE id = $1`, agentID, string(s))
		if err == nil && tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return err
	})
}

func (p *Postgres) ApproveAgent(ctx context.Context, tenantID, agentID, by string, at time.Time) error {
	return p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE agents SET status = 'active', approved_at = $2, approved_by = $3
			WHERE id = $1 AND status = 'pending'`, agentID, at, by)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 1 {
			// Wake the agent's session so queued jobs are delivered at once.
			if _, err := tx.Exec(ctx, `SELECT pg_notify($1, $2)`, jobsChannel, WakeKey(tenantID, agentID)); err != nil {
				return err
			}
		}
		if tag.RowsAffected() == 0 {
			var exists bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM agents WHERE id = $1)`, agentID).Scan(&exists); err != nil {
				return err
			}
			if exists {
				return ErrNotPending
			}
			return ErrNotFound
		}
		return nil
	})
}

func (p *Postgres) RotateAgentCert(ctx context.Context, tenantID, agentID, used, newFP string, notAfter time.Time) error {
	return p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE agents
			SET prev_cert_fingerprint = $2, cert_fingerprint = $3, cert_not_after = $4
			WHERE id = $1 AND status <> 'revoked' AND (cert_fingerprint = $2 OR prev_cert_fingerprint = $2)`,
			agentID, used, newFP, notAfter)
		if err == nil && tag.RowsAffected() == 0 {
			return ErrCertMismatch
		}
		return err
	})
}

func (p *Postgres) ForgetPrevCert(ctx context.Context, tenantID, agentID string) error {
	return p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE agents SET prev_cert_fingerprint = NULL WHERE id = $1`, agentID)
		return err
	})
}

func (p *Postgres) AppendAudit(ctx context.Context, e audit.Event) (audit.Event, error) {
	err := p.inTenant(ctx, e.TenantID, func(tx pgx.Tx) error {
		// Serialize appends per tenant so the chain cannot fork.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "audit:"+e.TenantID); err != nil {
			return err
		}
		seq, prev := int64(1), audit.GenesisHash
		var lastSeq int64
		var lastHash []byte
		err := tx.QueryRow(ctx, `SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1`).Scan(&lastSeq, &lastHash)
		switch {
		case err == nil:
			seq, prev = lastSeq+1, lastHash
		case !errors.Is(err, pgx.ErrNoRows):
			return err
		}
		e, err = prepareAudit(e, seq, prev)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO audit_log
			(tenant_id, seq, occurred_at, actor, action, target, details, prev_hash, hash)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
			e.TenantID, e.Seq, e.OccurredAt, e.Actor, e.Action, e.Target, e.Details, e.PrevHash, e.Hash)
		return err
	})
	return e, err
}

func (p *Postgres) ListAudit(ctx context.Context, tenantID string) ([]audit.Event, error) {
	var out []audit.Event
	err := p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT tenant_id::text, seq, occurred_at, actor, action, target, details,
			prev_hash, hash FROM audit_log ORDER BY seq`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e audit.Event
			if err := rows.Scan(&e.TenantID, &e.Seq, &e.OccurredAt, &e.Actor, &e.Action, &e.Target,
				&e.Details, &e.PrevHash, &e.Hash); err != nil {
				return err
			}
			e.OccurredAt = e.OccurredAt.UTC()
			out = append(out, e)
		}
		return rows.Err()
	})
	return out, err
}
