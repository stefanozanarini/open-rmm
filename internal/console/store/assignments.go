package store

import (
	"context"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
)

// Assignment is a permanent workflow assignment to a group: a revision
// approved once by an administrator (Envelope, a serialized SignedEnvelope
// carrying an assignreq.AssignmentRequest), run automatically on the
// group's computers until it expires or is revoked.
type Assignment struct {
	TenantID      string
	ID            string
	WorkflowID    string
	Revision      int
	GroupID       string
	Envelope      []byte
	MaxTTLSeconds int
	ExpiresAt     time.Time
	Active        bool
	CreatedBy     string
	CreatedAt     time.Time
	RevokedBy     string
	RevokedAt     *time.Time
}

// AssignmentStore keeps permanent workflow assignments.
type AssignmentStore interface {
	CreateAssignment(ctx context.Context, a Assignment) error
	// ListAssignments returns every assignment of the tenant (active and
	// revoked), newest first.
	ListAssignments(ctx context.Context, tenantID string) ([]Assignment, error)
	GetAssignment(ctx context.Context, tenantID, id string) (Assignment, error)
	// SetAssignmentActive pauses or resumes an assignment; it never
	// changes its signed content or expiry.
	SetAssignmentActive(ctx context.Context, tenantID, id string, active bool, by string, at time.Time) error
}

// ---- memory ----

func (m *Memory) CreateAssignment(_ context.Context, a Assignment) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.assignments == nil {
		m.assignments = map[string]Assignment{}
	}
	a.Envelope, a.Active = append([]byte(nil), a.Envelope...), true
	m.assignments[a.TenantID+"/"+a.ID] = a
	return nil
}

func (m *Memory) ListAssignments(_ context.Context, tenantID string) ([]Assignment, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Assignment
	for _, a := range m.assignments {
		if a.TenantID == tenantID {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (m *Memory) GetAssignment(_ context.Context, tenantID, id string) (Assignment, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.assignments[tenantID+"/"+id]
	if !ok {
		return Assignment{}, ErrNotFound
	}
	return a, nil
}

func (m *Memory) SetAssignmentActive(_ context.Context, tenantID, id string, active bool, by string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := tenantID + "/" + id
	a, ok := m.assignments[k]
	if !ok {
		return ErrNotFound
	}
	a.Active = active
	if !active {
		a.RevokedBy, a.RevokedAt = by, &at
	} else {
		a.RevokedBy, a.RevokedAt = "", nil
	}
	m.assignments[k] = a
	return nil
}

// ---- postgres ----

func (p *Postgres) CreateAssignment(ctx context.Context, a Assignment) error {
	return p.inTenant(ctx, a.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO workflow_assignments
			(tenant_id, id, workflow_id, revision, group_id, envelope, max_ttl_seconds, expires_at, created_by)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
			a.TenantID, a.ID, a.WorkflowID, a.Revision, a.GroupID, a.Envelope, a.MaxTTLSeconds, a.ExpiresAt, a.CreatedBy)
		return err
	})
}

const assignmentColumns = `id::text, workflow_id::text, revision, group_id::text, envelope, max_ttl_seconds,
	expires_at, active, created_by, created_at, revoked_by, revoked_at`

func scanAssignment(row pgx.Row, tenantID string) (Assignment, error) {
	a := Assignment{TenantID: tenantID}
	err := row.Scan(&a.ID, &a.WorkflowID, &a.Revision, &a.GroupID, &a.Envelope, &a.MaxTTLSeconds,
		&a.ExpiresAt, &a.Active, &a.CreatedBy, &a.CreatedAt, &a.RevokedBy, &a.RevokedAt)
	return a, err
}

func (p *Postgres) ListAssignments(ctx context.Context, tenantID string) ([]Assignment, error) {
	var out []Assignment
	err := p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+assignmentColumns+` FROM workflow_assignments ORDER BY created_at DESC`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			a, err := scanAssignment(rows, tenantID)
			if err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}

func (p *Postgres) GetAssignment(ctx context.Context, tenantID, id string) (Assignment, error) {
	var a Assignment
	err := p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		a, err = scanAssignment(tx.QueryRow(ctx, `SELECT `+assignmentColumns+` FROM workflow_assignments WHERE id = $1`, id), tenantID)
		return err
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			return Assignment{}, ErrNotFound
		}
		return Assignment{}, err
	}
	return a, nil
}

func (p *Postgres) SetAssignmentActive(ctx context.Context, tenantID, id string, active bool, by string, at time.Time) error {
	return p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		query, args := `UPDATE workflow_assignments SET active = true, revoked_by = '', revoked_at = NULL WHERE id = $1`, []any{id}
		if !active {
			query, args = `UPDATE workflow_assignments SET active = false, revoked_by = $2, revoked_at = $3 WHERE id = $1`,
				[]any{id, by, at}
		}
		tag, err := tx.Exec(ctx, query, args...)
		if err == nil && tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return err
	})
}
