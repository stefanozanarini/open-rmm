package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ErrStaleInventory is returned for an inventory older than the stored one.
var ErrStaleInventory = errors.New("inventory older than the stored one")

// maxChangesPerAgent bounds the change history kept per agent.
const maxChangesPerAgent = 2000

// InventorySummary holds the inventory fields shown in agent lists.
type InventorySummary struct {
	AgentID      string
	CollectedAt  time.Time
	Manufacturer string
	Model        string
	Serial       string
	LoggedOnUser string
	SupremoID    string
	AnyDeskID    string
	TeamViewerID string
	IPv4         []string // adapter addresses, for site matching
}

// Inventory is the latest inventory of an agent.
type Inventory struct {
	TenantID   string
	AgentID    string
	ReceivedAt time.Time
	Data       []byte // normalized JSON (internal/inventory)
	Summary    InventorySummary
}

// InventoryChange is one entry of an agent's change history.
type InventoryChange struct {
	At     time.Time
	Kind   string
	Detail string
}

// InventoryStore keeps inventories.
type InventoryStore interface {
	// PutInventory replaces the agent's inventory and appends changes,
	// unless the stored inventory is newer (ErrStaleInventory).
	PutInventory(ctx context.Context, inv Inventory, changes []InventoryChange) error
	GetInventory(ctx context.Context, tenantID, agentID string) (Inventory, error)
	// InventorySummaries returns the summaries of the tenant's agents, by agent id.
	InventorySummaries(ctx context.Context, tenantID string) (map[string]InventorySummary, error)
	// ListInventories returns the latest inventory of every agent of the tenant.
	ListInventories(ctx context.Context, tenantID string) ([]Inventory, error)
	// ListInventoryChanges returns the most recent changes first.
	ListInventoryChanges(ctx context.Context, tenantID, agentID string, limit int) ([]InventoryChange, error)
}

// ---- memory ----

type memInventory struct {
	inv     Inventory
	changes []InventoryChange // oldest first
}

func (m *Memory) PutInventory(_ context.Context, inv Inventory, changes []InventoryChange) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := agentKey(inv.TenantID, inv.AgentID)
	if _, ok := m.agents[k]; !ok {
		return ErrNotFound
	}
	cur := m.inventories[k]
	if cur != nil && cur.inv.Summary.CollectedAt.After(inv.Summary.CollectedAt) {
		return ErrStaleInventory
	}
	if cur == nil {
		cur = &memInventory{}
		m.inventories[k] = cur
	}
	if inv.ReceivedAt.IsZero() {
		inv.ReceivedAt = time.Now()
	}
	inv.Summary.AgentID = inv.AgentID
	cur.inv = inv
	cur.changes = append(cur.changes, changes...)
	if n := len(cur.changes) - maxChangesPerAgent; n > 0 {
		cur.changes = cur.changes[n:]
	}
	return nil
}

func (m *Memory) GetInventory(_ context.Context, tenantID, agentID string) (Inventory, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur := m.inventories[agentKey(tenantID, agentID)]
	if cur == nil {
		return Inventory{}, ErrNotFound
	}
	return cur.inv, nil
}

func (m *Memory) InventorySummaries(_ context.Context, tenantID string) (map[string]InventorySummary, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]InventorySummary{}
	for _, cur := range m.inventories {
		if cur.inv.TenantID == tenantID {
			out[cur.inv.AgentID] = cur.inv.Summary
		}
	}
	return out, nil
}

func (m *Memory) ListInventories(_ context.Context, tenantID string) ([]Inventory, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Inventory
	for _, cur := range m.inventories {
		if cur.inv.TenantID == tenantID {
			out = append(out, cur.inv)
		}
	}
	return out, nil
}

func (m *Memory) ListInventoryChanges(_ context.Context, tenantID, agentID string, limit int) ([]InventoryChange, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur := m.inventories[agentKey(tenantID, agentID)]
	if cur == nil {
		return nil, nil
	}
	var out []InventoryChange
	for i := len(cur.changes) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, cur.changes[i])
	}
	return out, nil
}

// ---- postgres ----

func (p *Postgres) PutInventory(ctx context.Context, inv Inventory, changes []InventoryChange) error {
	s := inv.Summary
	err := p.inTenant(ctx, inv.TenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO inventories (tenant_id, agent_id, collected_at, data, manufacturer, model,
			serial, logged_on_user, supremo_id, anydesk_id, teamviewer_id, ipv4) VALUES ($1,$2,$3,$4::jsonb,$5,$6,$7,$8,$9,$10,$11,$12)
			ON CONFLICT (tenant_id, agent_id) DO UPDATE SET collected_at = EXCLUDED.collected_at, received_at = now(),
			data = EXCLUDED.data, manufacturer = EXCLUDED.manufacturer, model = EXCLUDED.model, serial = EXCLUDED.serial,
			logged_on_user = EXCLUDED.logged_on_user, supremo_id = EXCLUDED.supremo_id, anydesk_id = EXCLUDED.anydesk_id,
			teamviewer_id = EXCLUDED.teamviewer_id, ipv4 = EXCLUDED.ipv4
			WHERE inventories.collected_at <= EXCLUDED.collected_at`,
			inv.TenantID, inv.AgentID, s.CollectedAt, string(inv.Data), s.Manufacturer, s.Model, s.Serial,
			s.LoggedOnUser, s.SupremoID, s.AnyDeskID, s.TeamViewerID, nonNil(s.IPv4))
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrStaleInventory
		}
		if len(changes) == 0 {
			return nil
		}
		// One INSERT for all changes (COPY is not allowed with row-level security).
		at := make([]time.Time, len(changes))
		kinds := make([]string, len(changes))
		details := make([]string, len(changes))
		for i, c := range changes {
			at[i], kinds[i], details[i] = c.At, c.Kind, c.Detail
		}
		if _, err := tx.Exec(ctx, `INSERT INTO inventory_changes (tenant_id, agent_id, at, kind, detail)
			SELECT $1, $2, a, k, d FROM unnest($3::timestamptz[], $4::text[], $5::text[]) WITH ORDINALITY AS c(a, k, d, n)
			ORDER BY n`, inv.TenantID, inv.AgentID, at, kinds, details); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `DELETE FROM inventory_changes WHERE agent_id = $1 AND seq < (
			SELECT min(seq) FROM (SELECT seq FROM inventory_changes WHERE agent_id = $1 ORDER BY seq DESC LIMIT $2) AS keep)`,
			inv.AgentID, maxChangesPerAgent)
		return err
	})
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23503" {
		return ErrNotFound
	}
	return err
}

const summaryColumns = `agent_id::text, collected_at, manufacturer, model, serial, logged_on_user, supremo_id, anydesk_id, teamviewer_id, ipv4`

func scanSummary(row pgx.Row, extra ...any) (InventorySummary, error) {
	var s InventorySummary
	dest := append([]any{&s.AgentID, &s.CollectedAt, &s.Manufacturer, &s.Model, &s.Serial, &s.LoggedOnUser,
		&s.SupremoID, &s.AnyDeskID, &s.TeamViewerID, &s.IPv4}, extra...)
	return s, row.Scan(dest...)
}

func (p *Postgres) GetInventory(ctx context.Context, tenantID, agentID string) (Inventory, error) {
	inv := Inventory{TenantID: tenantID, AgentID: agentID}
	err := p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var data string
		s, err := scanSummary(tx.QueryRow(ctx, `SELECT `+summaryColumns+`, received_at, data::text
			FROM inventories WHERE agent_id = $1`, agentID), &inv.ReceivedAt, &data)
		inv.Summary, inv.Data = s, []byte(data)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Inventory{}, ErrNotFound
	}
	return inv, err
}

func (p *Postgres) InventorySummaries(ctx context.Context, tenantID string) (map[string]InventorySummary, error) {
	out := map[string]InventorySummary{}
	err := p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+summaryColumns+` FROM inventories`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			s, err := scanSummary(rows)
			if err != nil {
				return err
			}
			out[s.AgentID] = s
		}
		return rows.Err()
	})
	return out, err
}

func (p *Postgres) ListInventories(ctx context.Context, tenantID string) ([]Inventory, error) {
	var out []Inventory
	err := p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+summaryColumns+`, received_at, data::text FROM inventories`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			inv := Inventory{TenantID: tenantID}
			var data string
			s, err := scanSummary(rows, &inv.ReceivedAt, &data)
			if err != nil {
				return err
			}
			inv.AgentID, inv.Summary, inv.Data = s.AgentID, s, []byte(data)
			out = append(out, inv)
		}
		return rows.Err()
	})
	return out, err
}

func (p *Postgres) ListInventoryChanges(ctx context.Context, tenantID, agentID string, limit int) ([]InventoryChange, error) {
	var out []InventoryChange
	err := p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT at, kind, detail FROM inventory_changes WHERE agent_id = $1
			ORDER BY seq DESC LIMIT $2`, agentID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c InventoryChange
			if err := rows.Scan(&c.At, &c.Kind, &c.Detail); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}
