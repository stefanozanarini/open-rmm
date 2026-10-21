package store

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/stefanozanarini/open-rmm/internal/ids"
)

// LogonRetention is how long logon events are kept.
const LogonRetention = 90 * 24 * time.Hour

// Settings are per-tenant options edited in the console.
type Settings struct {
	// RDPAllowedSubnets lists the networks RDP is expected from (CIDR).
	// Empty means the private ranges (RFC 1918, RFC 4193) and loopback.
	RDPAllowedSubnets []string `json:"rdp_allowed_subnets,omitempty"`
	// CodeSigningCert is the public Authenticode certificate (PEM, with its
	// CAs) the agent's MSI is signed with: offered for Group Policy and
	// watched for expiry. Never a key.
	CodeSigningCert string `json:"code_signing_cert,omitempty"`
	// ADReaders are the agents (domain member servers) that read Active
	// Directory every 24 hours, besides the domain controllers.
	ADReaders []string `json:"ad_readers,omitempty"`
	// Logo is the company logo shown in the console header (PNG, JPEG or
	// WebP, at most 256 KB), with its media type.
	Logo     []byte `json:"logo,omitempty"`
	LogoType string `json:"logo_type,omitempty"`
}

// Check statuses.
const (
	CheckOK      = "ok"
	CheckWarning = "warning"
	CheckFailing = "failing"
)

// Check is the latest result of a check reported by a module.
type Check struct {
	TenantID  string
	AgentID   string
	CheckID   string // "<module>/<id>"
	Status    string
	Summary   string
	UpdatedAt time.Time
}

// Alert severities.
const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// Alert is something an operator should look at.
type Alert struct {
	TenantID       string
	ID             string
	AgentID        string
	Severity       string
	Kind           string
	Summary        string
	DedupeKey      string
	Count          int
	FirstSeen      time.Time
	LastSeen       time.Time
	AcknowledgedAt *time.Time
	AcknowledgedBy string
	// Once: raise only if no alert with this key ever existed, even
	// acknowledged (for events with their own id, e.g. Vision One alerts).
	Once bool
}

// LogonEvent is a normalized logon event of an endpoint.
type LogonEvent struct {
	Channel    string // security | rcm | lsm
	RecordID   int64
	At         time.Time
	EventID    int
	Kind       string
	User       string
	Domain     string
	LogonType  int
	SourceIP   string
	SourceHost string
	Status     string
}

// AgentLogon is a logon event with its agent.
type AgentLogon struct {
	AgentID string
	LogonEvent
}

// SecurityStore keeps settings, checks, alerts and logon events.
type SecurityStore interface {
	GetSettings(ctx context.Context, tenantID string) (Settings, error)
	PutSettings(ctx context.Context, tenantID string, s Settings, by string) error

	// PutCheck stores a check result unless a newer one is stored, and
	// returns the previous status ("" when the check is new).
	PutCheck(ctx context.Context, c Check) (prev string, err error)
	ListChecks(ctx context.Context, tenantID, agentID string) ([]Check, error)
	// WorstChecks returns the worst check status of each agent.
	WorstChecks(ctx context.Context, tenantID string) (map[string]string, error)

	// RaiseAlert opens an alert, or updates the open alert with the same
	// dedupe key (count, last seen). It reports whether a new one was opened.
	RaiseAlert(ctx context.Context, a Alert) (bool, error)
	// ListAlerts returns alerts, most recent first; agentID "" means all.
	ListAlerts(ctx context.Context, tenantID, agentID string, openOnly bool, limit int) ([]Alert, error)
	AcknowledgeAlert(ctx context.Context, tenantID, id, by string, at time.Time) error

	// SearchLogons returns the logon events of every agent whose user name
	// contains user (any user when empty), since the given time, most
	// recent first.
	SearchLogons(ctx context.Context, tenantID, user string, since time.Time, limit int) ([]AgentLogon, error)
	// AddLogonEvents stores events not stored yet and returns them, oldest
	// first. Events older than LogonRetention are purged.
	AddLogonEvents(ctx context.Context, tenantID, agentID string, events []LogonEvent, now time.Time) ([]LogonEvent, error)
	// LogonHistory reports when the agent's first event was recorded and
	// whether user logged on successfully from ip before t.
	LogonHistory(ctx context.Context, tenantID, agentID, user, ip string, t time.Time) (first time.Time, seen bool, err error)
	ListLogonEvents(ctx context.Context, tenantID, agentID string, limit int) ([]LogonEvent, error)
}

// SuccessfulLogon reports whether an event is a successful logon.
func (e LogonEvent) SuccessfulLogon() bool {
	switch e.Kind {
	case "logon", "rdp_auth", "rdp_session_logon", "rdp_reconnect":
		return true
	}
	return false
}

var checkRank = map[string]int{CheckOK: 1, CheckWarning: 2, CheckFailing: 3}

// Worse returns the worse of two check statuses.
func Worse(a, b string) string {
	if checkRank[b] > checkRank[a] {
		return b
	}
	return a
}

// ---- memory ----

type memSecurity struct {
	settings map[string]Settings
	checks   map[string]Check // tenant/agent/check
	alerts   []Alert
	logons   map[string][]LogonEvent // tenant/agent
}

func (m *Memory) sec() *memSecurity {
	if m.security == nil {
		m.security = &memSecurity{settings: map[string]Settings{}, checks: map[string]Check{}, logons: map[string][]LogonEvent{}}
	}
	return m.security
}

func (m *Memory) GetSettings(_ context.Context, tenantID string) (Settings, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sec().settings[tenantID], nil
}

func (m *Memory) PutSettings(_ context.Context, tenantID string, s Settings, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sec().settings[tenantID] = s
	return nil
}

func (m *Memory) PutCheck(_ context.Context, c Check) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.agents[agentKey(c.TenantID, c.AgentID)]; !ok {
		return "", ErrNotFound
	}
	k := c.TenantID + "/" + c.AgentID + "/" + c.CheckID
	prev, ok := m.sec().checks[k]
	if ok && prev.UpdatedAt.After(c.UpdatedAt) {
		return prev.Status, nil
	}
	m.sec().checks[k] = c
	return prev.Status, nil
}

func (m *Memory) ListChecks(_ context.Context, tenantID, agentID string) ([]Check, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Check
	for _, c := range m.sec().checks {
		if c.TenantID == tenantID && c.AgentID == agentID {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CheckID < out[j].CheckID })
	return out, nil
}

func (m *Memory) WorstChecks(_ context.Context, tenantID string) (map[string]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]string{}
	for _, c := range m.sec().checks {
		if c.TenantID == tenantID {
			out[c.AgentID] = Worse(out[c.AgentID], c.Status)
		}
	}
	return out, nil
}

func (m *Memory) RaiseAlert(_ context.Context, a Alert) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.agents[agentKey(a.TenantID, a.AgentID)]; !ok {
		return false, ErrNotFound
	}
	sec := m.sec()
	if a.Once {
		for _, cur := range sec.alerts {
			if cur.TenantID == a.TenantID && cur.DedupeKey == a.DedupeKey {
				return false, nil
			}
		}
	}
	for i := range sec.alerts {
		cur := &sec.alerts[i]
		if cur.TenantID == a.TenantID && cur.DedupeKey == a.DedupeKey && cur.AcknowledgedAt == nil {
			cur.Count++
			if a.LastSeen.After(cur.LastSeen) {
				cur.LastSeen, cur.Summary, cur.Severity = a.LastSeen, a.Summary, a.Severity
			}
			return false, nil
		}
	}
	if a.ID == "" {
		a.ID = ids.NewUUID()
	}
	a.Count = 1
	sec.alerts = append(sec.alerts, a)
	return true, nil
}

func (m *Memory) ListAlerts(_ context.Context, tenantID, agentID string, openOnly bool, limit int) ([]Alert, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Alert
	for _, a := range m.sec().alerts {
		if a.TenantID != tenantID || (agentID != "" && a.AgentID != agentID) || (openOnly && a.AcknowledgedAt != nil) {
			continue
		}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *Memory) AcknowledgeAlert(_ context.Context, tenantID, id, by string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.sec().alerts {
		a := &m.sec().alerts[i]
		if a.TenantID == tenantID && a.ID == id {
			if a.AcknowledgedAt == nil {
				a.AcknowledgedAt, a.AcknowledgedBy = &at, by
			}
			return nil
		}
	}
	return ErrNotFound
}

func logonKey(e LogonEvent) string { return e.Channel + "/" + strconv.FormatInt(e.RecordID, 10) }

func (m *Memory) AddLogonEvents(_ context.Context, tenantID, agentID string, events []LogonEvent, now time.Time) ([]LogonEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.agents[agentKey(tenantID, agentID)]; !ok {
		return nil, ErrNotFound
	}
	k := agentKey(tenantID, agentID)
	cur := m.sec().logons[k]
	seen := map[string]bool{}
	kept := cur[:0]
	for _, e := range cur {
		if now.Sub(e.At) <= LogonRetention {
			kept = append(kept, e)
			seen[logonKey(e)] = true
		}
	}
	var added []LogonEvent
	for _, e := range events {
		if seen[logonKey(e)] || now.Sub(e.At) > LogonRetention {
			continue
		}
		seen[logonKey(e)] = true
		kept = append(kept, e)
		added = append(added, e)
	}
	m.sec().logons[k] = kept
	sort.SliceStable(added, func(i, j int) bool { return added[i].At.Before(added[j].At) })
	return added, nil
}

func (m *Memory) LogonHistory(_ context.Context, tenantID, agentID, user, ip string, t time.Time) (time.Time, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var first time.Time
	seen := false
	for _, e := range m.sec().logons[agentKey(tenantID, agentID)] {
		if first.IsZero() || e.At.Before(first) {
			first = e.At
		}
		if e.SuccessfulLogon() && e.User == user && e.SourceIP == ip && e.At.Before(t) {
			seen = true
		}
	}
	return first, seen, nil
}

func (m *Memory) ListLogonEvents(_ context.Context, tenantID, agentID string, limit int) ([]LogonEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := append([]LogonEvent(nil), m.sec().logons[agentKey(tenantID, agentID)]...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].At.After(out[j].At) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *Memory) SearchLogons(_ context.Context, tenantID, user string, since time.Time, limit int) ([]AgentLogon, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []AgentLogon
	for k, evs := range m.sec().logons {
		agent, ok := strings.CutPrefix(k, tenantID+"/")
		if !ok {
			continue
		}
		for _, e := range evs {
			if !e.At.Before(since) && strings.Contains(strings.ToLower(e.User), strings.ToLower(user)) {
				out = append(out, AgentLogon{AgentID: agent, LogonEvent: e})
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].At.After(out[j].At) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// ---- postgres ----

func (p *Postgres) GetSettings(ctx context.Context, tenantID string) (Settings, error) {
	var s Settings
	err := p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var raw []byte
		err := tx.QueryRow(ctx, `SELECT settings FROM tenant_settings`).Scan(&raw)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		return json.Unmarshal(raw, &s)
	})
	return s, err
}

func (p *Postgres) PutSettings(ctx context.Context, tenantID string, s Settings, by string) error {
	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO tenant_settings (tenant_id, settings, updated_by) VALUES ($1, $2, $3)
			ON CONFLICT (tenant_id) DO UPDATE SET settings = EXCLUDED.settings, updated_by = EXCLUDED.updated_by, updated_at = now()`,
			tenantID, raw, by)
		return err
	})
}

func fkNotFound(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23503" {
		return ErrNotFound
	}
	return err
}

func (p *Postgres) PutCheck(ctx context.Context, c Check) (string, error) {
	var prev string
	err := p.inTenant(ctx, c.TenantID, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT status FROM agent_checks WHERE agent_id = $1 AND check_id = $2 FOR UPDATE`,
			c.AgentID, c.CheckID).Scan(&prev)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO agent_checks (tenant_id, agent_id, check_id, status, summary, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (tenant_id, agent_id, check_id) DO UPDATE SET status = EXCLUDED.status,
			summary = EXCLUDED.summary, updated_at = EXCLUDED.updated_at WHERE agent_checks.updated_at <= EXCLUDED.updated_at`,
			c.TenantID, c.AgentID, c.CheckID, c.Status, c.Summary, c.UpdatedAt)
		return err
	})
	return prev, fkNotFound(err)
}

func (p *Postgres) ListChecks(ctx context.Context, tenantID, agentID string) ([]Check, error) {
	var out []Check
	err := p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT check_id, status, summary, updated_at FROM agent_checks
			WHERE agent_id = $1 ORDER BY check_id`, agentID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			c := Check{TenantID: tenantID, AgentID: agentID}
			if err := rows.Scan(&c.CheckID, &c.Status, &c.Summary, &c.UpdatedAt); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

func (p *Postgres) WorstChecks(ctx context.Context, tenantID string) (map[string]string, error) {
	out := map[string]string{}
	err := p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT agent_id::text, status FROM agent_checks`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a, s string
			if err := rows.Scan(&a, &s); err != nil {
				return err
			}
			out[a] = Worse(out[a], s)
		}
		return rows.Err()
	})
	return out, err
}

func (p *Postgres) RaiseAlert(ctx context.Context, a Alert) (bool, error) {
	if a.ID == "" {
		a.ID = ids.NewUUID()
	}
	var created bool
	err := p.inTenant(ctx, a.TenantID, func(tx pgx.Tx) error {
		if a.Once {
			var exists bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM alerts WHERE dedupe_key = $1)`, a.DedupeKey).Scan(&exists); err != nil || exists {
				return err
			}
		}
		tag, err := tx.Exec(ctx, `UPDATE alerts SET count = count + 1,
			summary = CASE WHEN $2 > last_seen THEN $3 ELSE summary END,
			severity = CASE WHEN $2 > last_seen THEN $4 ELSE severity END,
			last_seen = greatest(last_seen, $2)
			WHERE dedupe_key = $1 AND acknowledged_at IS NULL`, a.DedupeKey, a.LastSeen, a.Summary, a.Severity)
		if err != nil || tag.RowsAffected() > 0 {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO alerts (tenant_id, id, agent_id, severity, kind, summary, dedupe_key, first_seen, last_seen)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, a.TenantID, a.ID, a.AgentID, a.Severity, a.Kind, a.Summary, a.DedupeKey,
			a.FirstSeen, a.LastSeen)
		created = err == nil
		return err
	})
	return created, fkNotFound(err)
}

func (p *Postgres) ListAlerts(ctx context.Context, tenantID, agentID string, openOnly bool, limit int) ([]Alert, error) {
	var out []Alert
	err := p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id::text, agent_id::text, severity, kind, summary, dedupe_key, count, first_seen,
			last_seen, acknowledged_at, acknowledged_by FROM alerts
			WHERE ($1 = '' OR agent_id::text = $1) AND (NOT $2 OR acknowledged_at IS NULL)
			ORDER BY last_seen DESC LIMIT $3`, agentID, openOnly, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			a := Alert{TenantID: tenantID}
			if err := rows.Scan(&a.ID, &a.AgentID, &a.Severity, &a.Kind, &a.Summary, &a.DedupeKey, &a.Count, &a.FirstSeen,
				&a.LastSeen, &a.AcknowledgedAt, &a.AcknowledgedBy); err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}

func (p *Postgres) AcknowledgeAlert(ctx context.Context, tenantID, id, by string, at time.Time) error {
	return p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM alerts WHERE id = $1)`, id).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrNotFound
		}
		_, err := tx.Exec(ctx, `UPDATE alerts SET acknowledged_at = $2, acknowledged_by = $3
			WHERE id = $1 AND acknowledged_at IS NULL`, id, at, by)
		return err
	})
}

func (p *Postgres) AddLogonEvents(ctx context.Context, tenantID, agentID string, events []LogonEvent, now time.Time) ([]LogonEvent, error) {
	var added []LogonEvent
	err := p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM logon_events WHERE agent_id = $1 AND at < $2`,
			agentID, now.Add(-LogonRetention)); err != nil {
			return err
		}
		n := len(events)
		if n == 0 {
			return nil
		}
		ch, at, user, dom, ip, host, st, kind := make([]string, n), make([]time.Time, n), make([]string, n), make([]string, n),
			make([]string, n), make([]string, n), make([]string, n), make([]string, n)
		rec := make([]int64, n)
		eid, lt := make([]int32, n), make([]int32, n)
		for i, e := range events {
			ch[i], rec[i], at[i], kind[i], user[i], dom[i] = e.Channel, e.RecordID, e.At, e.Kind, e.User, e.Domain
			eid[i], lt[i] = int32(e.EventID), int32(e.LogonType) // #nosec G115 -- validated small values
			ip[i], host[i], st[i] = e.SourceIP, e.SourceHost, e.Status
		}
		rows, err := tx.Query(ctx, `INSERT INTO logon_events (tenant_id, agent_id, channel, record_id, at, event_id, kind,
			username, domain, logon_type, source_ip, source_host, status)
			SELECT $1, $2, c, r, a, e, k, u, d, l, i, h, s FROM unnest($3::text[], $4::bigint[], $5::timestamptz[],
				$6::int[], $7::text[], $8::text[], $9::text[], $10::int[], $11::text[], $12::text[], $13::text[])
				AS x(c, r, a, e, k, u, d, l, i, h, s)
			WHERE a >= $14
			ON CONFLICT DO NOTHING
			RETURNING channel, record_id, at, event_id, kind, username, domain, logon_type, source_ip, source_host, status`,
			tenantID, agentID, ch, rec, at, eid, kind, user, dom, lt, ip, host, st, now.Add(-LogonRetention))
		if err != nil {
			return err
		}
		added, err = scanLogons(rows)
		return err
	})
	sort.SliceStable(added, func(i, j int) bool { return added[i].At.Before(added[j].At) })
	return added, fkNotFound(err)
}

func scanLogons(rows pgx.Rows) ([]LogonEvent, error) {
	defer rows.Close()
	var out []LogonEvent
	for rows.Next() {
		var e LogonEvent
		var eid, lt int32
		if err := rows.Scan(&e.Channel, &e.RecordID, &e.At, &eid, &e.Kind, &e.User, &e.Domain, &lt, &e.SourceIP,
			&e.SourceHost, &e.Status); err != nil {
			return nil, err
		}
		e.EventID, e.LogonType = int(eid), int(lt)
		out = append(out, e)
	}
	return out, rows.Err()
}

func (p *Postgres) LogonHistory(ctx context.Context, tenantID, agentID, user, ip string, t time.Time) (time.Time, bool, error) {
	var first *time.Time
	var seen bool
	err := p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT (SELECT min(at) FROM logon_events WHERE agent_id = $1),
			EXISTS (SELECT 1 FROM logon_events WHERE agent_id = $1 AND username = $2 AND source_ip = $3 AND at < $4
				AND kind IN ('logon', 'rdp_auth', 'rdp_session_logon', 'rdp_reconnect'))`,
			agentID, user, ip, t).Scan(&first, &seen)
	})
	if first == nil {
		return time.Time{}, seen, err
	}
	return *first, seen, err
}

func (p *Postgres) SearchLogons(ctx context.Context, tenantID, user string, since time.Time, limit int) ([]AgentLogon, error) {
	var out []AgentLogon
	err := p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT agent_id::text, channel, record_id, at, event_id, kind, username, domain, logon_type,
			source_ip, source_host, status FROM logon_events
			WHERE at >= $1 AND strpos(lower(username), lower($2)) > 0 ORDER BY at DESC, record_id DESC LIMIT $3`, since, user, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e AgentLogon
			var eid, lt int32
			if err := rows.Scan(&e.AgentID, &e.Channel, &e.RecordID, &e.At, &eid, &e.Kind, &e.User, &e.Domain, &lt,
				&e.SourceIP, &e.SourceHost, &e.Status); err != nil {
				return err
			}
			e.EventID, e.LogonType = int(eid), int(lt)
			out = append(out, e)
		}
		return rows.Err()
	})
	return out, err
}

func (p *Postgres) ListLogonEvents(ctx context.Context, tenantID, agentID string, limit int) ([]LogonEvent, error) {
	var out []LogonEvent
	err := p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT channel, record_id, at, event_id, kind, username, domain, logon_type, source_ip,
			source_host, status FROM logon_events WHERE agent_id = $1 ORDER BY at DESC, record_id DESC LIMIT $2`, agentID, limit)
		if err != nil {
			return err
		}
		out, err = scanLogons(rows)
		return err
	})
	return out, err
}
