package visionone

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/console/store"
)

// Thresholds.
const (
	// StaleAfter: an agent that Vision One has not heard from for this long
	// while open-rmm sees the endpoint online is reported.
	StaleAfter = 24 * time.Hour
	// onlineWindow: an agent seen by open-rmm this recently is online.
	onlineWindow = 30 * time.Minute
	lookBack     = 24 * time.Hour
)

// Syncer copies the Vision One view of a tenant's endpoints into checks
// and alerts.
type Syncer struct {
	Client   *Client
	Store    store.Store
	TenantID string
	Log      *slog.Logger
	Interval time.Duration
	Now      func() time.Time

	lastAlerts time.Time
}

// Run synchronizes every Interval until ctx ends.
func (s *Syncer) Run(ctx context.Context) {
	if s.Interval <= 0 {
		s.Interval = 15 * time.Minute
	}
	for {
		if err := s.Sync(ctx); err != nil && ctx.Err() == nil {
			s.Log.Error("vision one sync failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(s.Interval):
		}
	}
}

func (s *Syncer) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// shortName lowercases a host name and drops its domain.
func shortName(n string) string {
	n = strings.ToLower(strings.TrimSpace(n))
	if i := strings.IndexByte(n, '.'); i > 0 {
		n = n[:i]
	}
	return n
}

func parseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}

// Sync performs one synchronization.
func (s *Syncer) Sync(ctx context.Context) error {
	now := s.now()
	agents, err := s.Store.ListAgents(ctx, s.TenantID)
	if err != nil {
		return err
	}
	byName := map[string][]store.Agent{}
	for _, a := range agents {
		if a.Status == store.AgentActive && a.Host.OS == "windows" {
			byName[shortName(a.Host.Hostname)] = append(byName[shortName(a.Host.Hostname)], a)
		}
	}
	eps, err := s.Client.Endpoints(ctx)
	if err != nil {
		return err
	}
	found := map[string]bool{}
	for _, ep := range eps {
		for _, a := range byName[shortName(ep.EndpointName)] {
			found[a.ID] = true
			s.endpointChecks(ctx, a, ep, now)
		}
	}
	for _, list := range byName {
		for _, a := range list {
			if found[a.ID] {
				continue
			}
			status := store.CheckWarning
			if a.LastSeenAt == nil || now.Sub(*a.LastSeenAt) > onlineWindow {
				status = store.CheckOK // offline: nothing to compare
			}
			summary := "Endpoint non presente nell'inventario di Vision One"
			if status == store.CheckOK {
				summary = "Endpoint non presente in Vision One (offline anche per open-rmm)"
			}
			s.put(ctx, a, "registered", status, summary, now)
		}
	}

	since := s.lastAlerts
	if since.IsZero() {
		since = now.Add(-lookBack)
	}
	alerts, err := s.Client.Alerts(ctx, since.Add(-5*time.Minute), now)
	if err != nil {
		return err
	}
	for _, al := range alerts {
		for _, h := range al.Hosts() {
			for _, a := range byName[shortName(h)] {
				s.raiseWorkbench(ctx, a, al, now)
			}
		}
	}
	s.lastAlerts = now
	s.Log.Info("vision one synchronized", "endpoints", len(eps), "matched", len(found), "alerts", len(alerts))
	return nil
}

func (s *Syncer) put(ctx context.Context, a store.Agent, id, status, summary string, now time.Time) {
	prev, err := s.Store.PutCheck(ctx, store.Check{TenantID: a.TenantID, AgentID: a.ID, CheckID: "visionone/" + id,
		Status: status, Summary: summary, UpdatedAt: now})
	if err != nil {
		s.Log.Error("store vision one check", "agent", a.ID, "err", err)
		return
	}
	if status == store.CheckFailing && prev != store.CheckFailing {
		s.raise(ctx, store.Alert{TenantID: a.TenantID, AgentID: a.ID, Severity: store.SeverityWarning, Kind: "check.failing",
			DedupeKey: a.ID + "/check/visionone/" + id, Summary: "Vision One: " + summary, FirstSeen: now, LastSeen: now})
	}
}

func (s *Syncer) endpointChecks(ctx context.Context, a store.Agent, ep Endpoint, now time.Time) {
	online := a.LastSeenAt != nil && now.Sub(*a.LastSeenAt) <= onlineWindow
	if epp := ep.EPPAgent; epp != nil && (epp.Status != "" || epp.Version != "") {
		last := parseTime(epp.LastConnectedDateTime)
		status, summary := store.CheckOK, fmt.Sprintf("Protezione endpoint %s, versione %s", orDash(epp.Status), orDash(epp.Version))
		switch {
		case epp.Status != "" && !strings.EqualFold(epp.Status, "on") && !strings.EqualFold(epp.Status, "enabled"):
			status = store.CheckFailing
		case online && !last.IsZero() && now.Sub(last) > StaleAfter:
			status = store.CheckFailing
			summary = fmt.Sprintf("Agente di protezione non connesso a Vision One dal %s, ma il PC è online", last.Local().Format("02/01/2006 15:04"))
		case strings.EqualFold(epp.ComponentUpdateStatus, "outdated"):
			status = store.CheckWarning
			summary += ", componenti non aggiornati"
		}
		s.put(ctx, a, "protection", status, summary, now)
	}
	if edr := ep.EDRSensor; edr != nil && (edr.Status != "" || edr.Connectivity != "") {
		status, summary := store.CheckOK, fmt.Sprintf("Sensore %s, %s", orDash(edr.Status), orDash(edr.Connectivity))
		switch {
		case strings.EqualFold(edr.Status, "disabled"):
			status = store.CheckWarning
		case online && strings.EqualFold(edr.Connectivity, "disconnected"):
			status = store.CheckFailing
			summary = "Sensore Vision One disconnesso mentre il PC è online"
		}
		s.put(ctx, a, "sensor", status, summary, now)
	}
	s.put(ctx, a, "registered", store.CheckOK, "Presente in Vision One ("+ep.EndpointName+")", now)
}

var severities = map[string]string{"critical": store.SeverityCritical, "high": store.SeverityCritical,
	"medium": store.SeverityWarning, "low": store.SeverityInfo}

func (s *Syncer) raiseWorkbench(ctx context.Context, a store.Agent, al Alert, now time.Time) {
	sev, ok := severities[strings.ToLower(al.Severity)]
	if !ok {
		sev = store.SeverityWarning
	}
	at := parseTime(al.CreatedDateTime)
	if at.IsZero() {
		at = now
	}
	summary := fmt.Sprintf("Vision One Workbench %s: %s (gravità %s, punteggio %d)", al.ID, al.Model, al.Severity, al.Score)
	s.raise(ctx, store.Alert{TenantID: a.TenantID, AgentID: a.ID, Severity: sev, Kind: "visionone.workbench",
		DedupeKey: a.ID + "/visionone/" + al.ID, Summary: summary, FirstSeen: at, LastSeen: at, Once: true})
}

func (s *Syncer) raise(ctx context.Context, al store.Alert) {
	created, err := s.Store.RaiseAlert(ctx, al)
	if err != nil {
		s.Log.Error("raise alert", "err", err)
		return
	}
	if created {
		s.Log.Warn("alert", "agent", al.AgentID, "severity", al.Severity, "kind", al.Kind, "summary", al.Summary)
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
