package store

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ErrWorkflowExists is returned for a duplicate workflow name.
var ErrWorkflowExists = errors.New("a workflow with this name exists")

// Workflow is a software distribution workflow with one of its revisions
// (the latest, in listings).
type Workflow struct {
	TenantID    string
	ID          string
	Name        string
	Description string
	CreatedBy   string
	CreatedAt   time.Time

	Revision  int
	Document  []byte // workflow.Document as JSON
	Comment   string
	Author    string
	UpdatedAt time.Time
}

// WorkflowStore keeps workflows and their revisions.
type WorkflowStore interface {
	// SaveWorkflow creates the workflow, or renames it, and adds a revision
	// with w's Document, Comment and Author; it returns the revision number.
	SaveWorkflow(ctx context.Context, w Workflow) (int, error)
	DeleteWorkflow(ctx context.Context, tenantID, id string) error
	// ListWorkflows returns the workflows with their latest revision.
	ListWorkflows(ctx context.Context, tenantID string) ([]Workflow, error)
	// GetWorkflow returns a revision of a workflow; 0 is the latest.
	GetWorkflow(ctx context.Context, tenantID, id string, revision int) (Workflow, error)
	// WorkflowRevisions lists the revisions, newest first, without documents.
	WorkflowRevisions(ctx context.Context, tenantID, id string) ([]Workflow, error)
}

// ---- memory ----

type memWorkflow struct {
	head      Workflow
	revisions []Workflow // revision i+1
}

func (m *Memory) SaveWorkflow(_ context.Context, w Workflow) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.workflows == nil {
		m.workflows = map[string]*memWorkflow{}
	}
	for k, cur := range m.workflows {
		if cur.head.TenantID == w.TenantID && cur.head.Name == w.Name && k != w.TenantID+"/"+w.ID {
			return 0, ErrWorkflowExists
		}
	}
	now := time.Now()
	cur, ok := m.workflows[w.TenantID+"/"+w.ID]
	if !ok {
		cur = &memWorkflow{head: Workflow{TenantID: w.TenantID, ID: w.ID, CreatedBy: w.Author, CreatedAt: now}}
		m.workflows[w.TenantID+"/"+w.ID] = cur
	}
	cur.head.Name, cur.head.Description = w.Name, w.Description
	rev := cur.head
	rev.Revision, rev.Document, rev.Comment, rev.Author, rev.UpdatedAt = len(cur.revisions)+1, append([]byte(nil), w.Document...), w.Comment, w.Author, now
	cur.revisions = append(cur.revisions, rev)
	return rev.Revision, nil
}

func (m *Memory) DeleteWorkflow(_ context.Context, tenantID, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.workflows[tenantID+"/"+id]; !ok {
		return ErrNotFound
	}
	delete(m.workflows, tenantID+"/"+id)
	return nil
}

// revision returns revision n (0: the latest) with the current name.
func (w *memWorkflow) revision(n int) (Workflow, bool) {
	if n == 0 {
		n = len(w.revisions)
	}
	if n < 1 || n > len(w.revisions) {
		return Workflow{}, false
	}
	r := w.revisions[n-1]
	r.Name, r.Description = w.head.Name, w.head.Description
	return r, true
}

func (m *Memory) ListWorkflows(_ context.Context, tenantID string) ([]Workflow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Workflow
	for _, w := range m.workflows {
		if w.head.TenantID == tenantID {
			r, _ := w.revision(0)
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *Memory) GetWorkflow(_ context.Context, tenantID, id string, revision int) (Workflow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	w, ok := m.workflows[tenantID+"/"+id]
	if !ok {
		return Workflow{}, ErrNotFound
	}
	r, ok := w.revision(revision)
	if !ok {
		return Workflow{}, ErrNotFound
	}
	return r, nil
}

func (m *Memory) WorkflowRevisions(_ context.Context, tenantID, id string) ([]Workflow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	w, ok := m.workflows[tenantID+"/"+id]
	if !ok {
		return nil, ErrNotFound
	}
	var out []Workflow
	for i := len(w.revisions); i > 0; i-- {
		r, _ := w.revision(i)
		r.Document = nil
		out = append(out, r)
	}
	return out, nil
}

// ---- postgres ----

func (p *Postgres) SaveWorkflow(ctx context.Context, w Workflow) (int, error) {
	var rev int
	err := p.inTenant(ctx, w.TenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO workflows (tenant_id, id, name, description, created_by) VALUES ($1,$2,$3,$4,$5)
			ON CONFLICT (tenant_id, id) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description`,
			w.TenantID, w.ID, w.Name, w.Description, w.Author); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `INSERT INTO workflow_revisions (tenant_id, workflow_id, revision, document, comment, author)
			SELECT $1, $2, COALESCE(MAX(revision), 0) + 1, $3::jsonb, $4, $5 FROM workflow_revisions WHERE workflow_id = $2
			RETURNING revision`, w.TenantID, w.ID, jsonbText(w.Document), w.Comment, w.Author).Scan(&rev)
	})
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "workflows_tenant_id_name_key" {
		return 0, ErrWorkflowExists
	}
	return rev, err
}

func (p *Postgres) DeleteWorkflow(ctx context.Context, tenantID, id string) error {
	return p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM workflows WHERE id = $1`, id)
		if err == nil && tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return err
	})
}

const workflowColumns = `w.id::text, w.name, w.description, w.created_by, w.created_at, r.revision, r.comment, r.author, r.created_at`

func scanWorkflow(row pgx.Row, w *Workflow, extra ...any) error {
	return row.Scan(append([]any{&w.ID, &w.Name, &w.Description, &w.CreatedBy, &w.CreatedAt, &w.Revision, &w.Comment, &w.Author, &w.UpdatedAt}, extra...)...)
}

func (p *Postgres) ListWorkflows(ctx context.Context, tenantID string) ([]Workflow, error) {
	var out []Workflow
	err := p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+workflowColumns+`, r.document::text FROM workflows w
			JOIN LATERAL (SELECT * FROM workflow_revisions x WHERE x.tenant_id = w.tenant_id AND x.workflow_id = w.id
				ORDER BY revision DESC LIMIT 1) r ON true ORDER BY w.name`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			w := Workflow{TenantID: tenantID}
			var doc string
			if err := scanWorkflow(rows, &w, &doc); err != nil {
				return err
			}
			w.Document = []byte(doc)
			out = append(out, w)
		}
		return rows.Err()
	})
	return out, err
}

func (p *Postgres) GetWorkflow(ctx context.Context, tenantID, id string, revision int) (Workflow, error) {
	w := Workflow{TenantID: tenantID}
	err := p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var doc string
		err := scanWorkflow(tx.QueryRow(ctx, `SELECT `+workflowColumns+`, r.document::text FROM workflows w
			JOIN workflow_revisions r ON r.tenant_id = w.tenant_id AND r.workflow_id = w.id
			WHERE w.id = $1 AND ($2 = 0 OR r.revision = $2) ORDER BY r.revision DESC LIMIT 1`, id, revision), &w, &doc)
		w.Document = []byte(doc)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Workflow{}, ErrNotFound
	}
	return w, err
}

func (p *Postgres) WorkflowRevisions(ctx context.Context, tenantID, id string) ([]Workflow, error) {
	var out []Workflow
	err := p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+workflowColumns+` FROM workflows w
			JOIN workflow_revisions r ON r.tenant_id = w.tenant_id AND r.workflow_id = w.id
			WHERE w.id = $1 ORDER BY r.revision DESC`, id)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			w := Workflow{TenantID: tenantID}
			if err := scanWorkflow(rows, &w); err != nil {
				return err
			}
			out = append(out, w)
		}
		return rows.Err()
	})
	if err == nil && len(out) == 0 {
		return nil, ErrNotFound
	}
	return out, err
}
