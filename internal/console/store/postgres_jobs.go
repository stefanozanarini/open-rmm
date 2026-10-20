package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const jobsChannel = "openrmm_jobs"

func (p *Postgres) PutModule(ctx context.Context, m Module) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO modules
		(id, version, description, key_id, manifest, signature, manifest_sha256, archive, uploaded_by, params)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		m.ID, m.Version, m.Description, m.KeyID, m.Manifest, m.Signature, m.ManifestSHA256, m.Archive, m.UploadedBy, m.Params)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return ErrModuleExists
	}
	return err
}

func (p *Postgres) GetModule(ctx context.Context, id, version string) (Module, error) {
	var m Module
	err := p.pool.QueryRow(ctx, `SELECT id, version, description, key_id, manifest, signature,
		manifest_sha256, archive, uploaded_at, uploaded_by, params FROM modules WHERE id = $1 AND version = $2`, id, version).
		Scan(&m.ID, &m.Version, &m.Description, &m.KeyID, &m.Manifest, &m.Signature, &m.ManifestSHA256,
			&m.Archive, &m.UploadedAt, &m.UploadedBy, &m.Params)
	if errors.Is(err, pgx.ErrNoRows) {
		return Module{}, ErrNotFound
	}
	return m, err
}

func (p *Postgres) ListModules(ctx context.Context) ([]Module, error) {
	rows, err := p.pool.Query(ctx, `SELECT id, version, description, key_id, manifest, signature,
		manifest_sha256, uploaded_at, uploaded_by, params FROM modules ORDER BY id, version`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Module
	for rows.Next() {
		var m Module
		if err := rows.Scan(&m.ID, &m.Version, &m.Description, &m.KeyID, &m.Manifest, &m.Signature,
			&m.ManifestSHA256, &m.UploadedAt, &m.UploadedBy, &m.Params); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (p *Postgres) CreateJob(ctx context.Context, j Job) error {
	params := j.Params
	if len(params) == 0 {
		params = []byte("{}")
	}
	err := p.inTenant(ctx, j.TenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO jobs
			(tenant_id, id, agent_id, module, module_version, action, params, envelope, state, created_by, expires_at, packages)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'queued',$9,$10,$11)`,
			j.TenantID, j.ID, j.AgentID, j.Module, j.ModuleVersion, j.Action, string(params), j.Envelope,
			j.CreatedBy, j.ExpiresAt, nonNil(j.Packages)); err != nil {
			return err
		}
		// Delivered on commit.
		_, err := tx.Exec(ctx, `SELECT pg_notify($1, $2)`, jobsChannel, WakeKey(j.TenantID, j.AgentID))
		return err
	})
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23503" {
		return ErrNotFound
	}
	return err
}

const jobColumns = `tenant_id::text, id::text, agent_id::text, module, module_version, action, params::text,
	envelope, state, progress, message, coalesce(result::text, ''), error, created_by, created_at, expires_at,
	sent_at, finished_at, packages`

func scanJob(row pgx.Row) (Job, error) {
	var j Job
	var state, params, result string
	var progress int16
	err := row.Scan(&j.TenantID, &j.ID, &j.AgentID, &j.Module, &j.ModuleVersion, &j.Action, &params,
		&j.Envelope, &state, &progress, &j.Message, &result, &j.Error, &j.CreatedBy, &j.CreatedAt,
		&j.ExpiresAt, &j.SentAt, &j.FinishedAt, &j.Packages)
	j.State, j.Progress, j.Params = JobState(state), int(progress), []byte(params)
	if result != "" {
		j.Result = []byte(result)
	}
	return j, err
}

func (p *Postgres) GetJob(ctx context.Context, tenantID, jobID string) (Job, error) {
	var j Job
	err := p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		j, err = scanJob(tx.QueryRow(ctx, `SELECT `+jobColumns+` FROM jobs WHERE id = $1`, jobID))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Job{}, ErrNotFound
	}
	return j, err
}

func (p *Postgres) queryJobs(ctx context.Context, tenantID, sql string, args ...any) ([]Job, error) {
	var out []Job
	err := p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, sql, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			j, err := scanJob(rows)
			if err != nil {
				return err
			}
			out = append(out, j)
		}
		return rows.Err()
	})
	return out, err
}

func (p *Postgres) ListJobs(ctx context.Context, tenantID, agentID string, limit int) ([]Job, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if agentID == "" {
		return p.queryJobs(ctx, tenantID, `SELECT `+jobColumns+` FROM jobs ORDER BY created_at DESC LIMIT $1`, limit)
	}
	return p.queryJobs(ctx, tenantID, `SELECT `+jobColumns+` FROM jobs WHERE agent_id = $1
		ORDER BY created_at DESC LIMIT $2`, agentID, limit)
}

func (p *Postgres) DispatchableJobs(ctx context.Context, tenantID, agentID string, now time.Time) ([]Job, error) {
	return p.queryJobs(ctx, tenantID, `SELECT `+jobColumns+` FROM jobs
		WHERE agent_id = $1 AND state IN ('queued', 'sent') AND expires_at > $2
		ORDER BY created_at LIMIT 100`, agentID, now)
}

func (p *Postgres) MarkJobSent(ctx context.Context, tenantID, jobID string, at time.Time) error {
	return p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE jobs SET state = CASE WHEN state = 'queued' THEN 'sent' ELSE state END,
			sent_at = $2, updated_at = $2 WHERE id = $1`, jobID, at)
		return err
	})
}

func (p *Postgres) UpdateJob(ctx context.Context, tenantID, agentID, jobID string, u JobUpdate, at time.Time) error {
	return p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var state string
		err := tx.QueryRow(ctx, `SELECT state FROM jobs WHERE id = $1 AND agent_id = $2 FOR UPDATE`, jobID, agentID).Scan(&state)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if JobState(state).Final() {
			if JobState(state) == u.State {
				return nil // duplicate delivery from the agent outbox
			}
			return ErrJobFinal
		}
		var result *string
		var finished *time.Time
		if u.State.Final() {
			finished = &at
			if len(u.Result) > 0 {
				r := string(u.Result)
				result = &r
			}
		}
		_, err = tx.Exec(ctx, `UPDATE jobs SET state = $2, progress = $3, message = $4, error = $5,
			result = coalesce($6::jsonb, result), finished_at = coalesce($7, finished_at), updated_at = $8
			WHERE id = $1`, jobID, string(u.State), u.Progress, u.Message, u.Error, result, finished, at)
		return err
	})
}

// ListenJobs holds one dedicated connection in LISTEN mode.
func (p *Postgres) ListenJobs(ctx context.Context, fn func(string)) error {
	conn, err := p.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "LISTEN "+jobsChannel); err != nil {
		return err
	}
	for {
		n, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		fn(n.Payload)
	}
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
