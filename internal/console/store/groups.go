package store

import (
	"context"
	"errors"
	"slices"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Group kinds.
const (
	GroupComputer = "computer"
	GroupUser     = "user"
)

// ErrGroupExists is returned for a duplicate group name of the same owner.
var ErrGroupExists = errors.New("a group with this name exists")

// Group is a set of computers or of users. Owner is the operator of a
// personal group, "" for a public one.
type Group struct {
	TenantID  string
	ID        string
	Name      string
	Kind      string // computer | user
	Owner     string
	Members   []string // agent ids, or user names (DOMAIN\user), sorted
	CreatedBy string
	CreatedAt time.Time
}

// GroupStore keeps groups and their members.
type GroupStore interface {
	// PutGroup creates a group, or renames it: Kind, Owner and Members of
	// an existing group are left as they are.
	PutGroup(ctx context.Context, g Group) error
	DeleteGroup(ctx context.Context, tenantID, id string) error
	// ListGroups returns every group of the tenant with its members.
	ListGroups(ctx context.Context, tenantID string) ([]Group, error)
	AddGroupMembers(ctx context.Context, tenantID, id string, members []string) error
	RemoveGroupMembers(ctx context.Context, tenantID, id string, members []string) error
}

// ---- memory ----

func (m *Memory) PutGroup(_ context.Context, g Group) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.groups == nil {
		m.groups = map[string]Group{}
	}
	k := g.TenantID + "/" + g.ID
	old, exists := m.groups[k]
	if exists {
		g.Owner = old.Owner
	}
	for _, cur := range m.groups {
		if cur.TenantID == g.TenantID && cur.Owner == g.Owner && cur.Name == g.Name && cur.ID != g.ID {
			return ErrGroupExists
		}
	}
	if exists {
		old.Name = g.Name
		m.groups[k] = old
		return nil
	}
	if g.CreatedAt.IsZero() {
		g.CreatedAt = time.Now()
	}
	g.Members = nil
	m.groups[k] = g
	return nil
}

func (m *Memory) DeleteGroup(_ context.Context, tenantID, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.groups[tenantID+"/"+id]; !ok {
		return ErrNotFound
	}
	delete(m.groups, tenantID+"/"+id)
	return nil
}

func (m *Memory) ListGroups(_ context.Context, tenantID string) ([]Group, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Group
	for _, g := range m.groups {
		if g.TenantID == tenantID {
			g.Members = slices.Clone(g.Members)
			out = append(out, g)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *Memory) AddGroupMembers(_ context.Context, tenantID, id string, members []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.groups[tenantID+"/"+id]
	if !ok {
		return ErrNotFound
	}
	for _, x := range members {
		if !slices.Contains(g.Members, x) {
			g.Members = append(g.Members, x)
		}
	}
	slices.Sort(g.Members)
	m.groups[tenantID+"/"+id] = g
	return nil
}

func (m *Memory) RemoveGroupMembers(_ context.Context, tenantID, id string, members []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.groups[tenantID+"/"+id]
	if !ok {
		return ErrNotFound
	}
	g.Members = slices.DeleteFunc(g.Members, func(x string) bool { return slices.Contains(members, x) })
	m.groups[tenantID+"/"+id] = g
	return nil
}

// ---- postgres ----

func (p *Postgres) PutGroup(ctx context.Context, g Group) error {
	err := p.inTenant(ctx, g.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO target_groups (tenant_id, id, name, kind, owner, created_by) VALUES ($1,$2,$3,$4,$5,$6)
			ON CONFLICT (tenant_id, id) DO UPDATE SET name = EXCLUDED.name`,
			g.TenantID, g.ID, g.Name, g.Kind, g.Owner, g.CreatedBy)
		return err
	})
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return ErrGroupExists
	}
	return err
}

func (p *Postgres) DeleteGroup(ctx context.Context, tenantID, id string) error {
	return p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM target_groups WHERE id = $1`, id)
		if err == nil && tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return err
	})
}

func (p *Postgres) ListGroups(ctx context.Context, tenantID string) ([]Group, error) {
	var out []Group
	err := p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT g.id::text, g.name, g.kind, g.owner, g.created_by, g.created_at,
				COALESCE(array_agg(m.member ORDER BY m.member) FILTER (WHERE m.member IS NOT NULL), '{}')
			FROM target_groups g LEFT JOIN target_group_members m ON m.tenant_id = g.tenant_id AND m.group_id = g.id
			GROUP BY g.id, g.name, g.kind, g.owner, g.created_by, g.created_at ORDER BY g.name`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			g := Group{TenantID: tenantID}
			if err := rows.Scan(&g.ID, &g.Name, &g.Kind, &g.Owner, &g.CreatedBy, &g.CreatedAt, &g.Members); err != nil {
				return err
			}
			if len(g.Members) == 0 {
				g.Members = nil
			}
			out = append(out, g)
		}
		return rows.Err()
	})
	return out, err
}

func (p *Postgres) AddGroupMembers(ctx context.Context, tenantID, id string, members []string) error {
	err := p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO target_group_members (tenant_id, group_id, member)
			SELECT $1, $2, unnest($3::text[]) ON CONFLICT DO NOTHING`, tenantID, id, nonNil(members))
		return err
	})
	return fkNotFound(err)
}

func (p *Postgres) RemoveGroupMembers(ctx context.Context, tenantID, id string, members []string) error {
	return p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM target_group_members WHERE group_id = $1 AND member = ANY($2)`, id, nonNil(members))
		return err
	})
}
