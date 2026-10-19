package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/accesslog"
	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/inventory"
	"github.com/stefanozanarini/open-rmm/internal/policy"
	"github.com/stefanozanarini/open-rmm/internal/updates"
)

// jobOrigin returns the module and action of a job of agent a, from the
// console's own records (never from the agent).
func (s *Server) jobOrigin(ctx context.Context, a store.Agent, jobID string) (module, action string, ok bool) {
	j, err := s.store.GetJob(ctx, a.TenantID, jobID)
	if err != nil || j.AgentID != a.ID {
		return "", "", false
	}
	return j.Module, j.Action, true
}

// ruleOrigin returns the module and action of a policy rule.
func (s *Server) ruleOrigin(ctx context.Context, tenantID, policyID, ruleID string) (module, action string, ok bool) {
	pv, err := s.store.GetPolicy(ctx, tenantID, policyID)
	if err != nil {
		return "", "", false
	}
	p, err := policy.Parse(pv.Document)
	if err != nil {
		return "", "", false
	}
	for _, r := range p.Rules {
		if r.ID == ruleID {
			return r.Module, r.Action, true
		}
	}
	return "", "", false
}

// afterSuccess processes the result of a successful module run: checks
// reported by any module, inventories and logon events.
func (s *Server) afterSuccess(ctx context.Context, a store.Agent, module, action string, raw []byte) {
	s.ingestChecks(ctx, a, module, raw)
	switch {
	case module == inventory.ModuleID && action == inventory.Action:
		s.ingestInventory(ctx, a, raw)
	case module == accesslog.ModuleID && action == accesslog.Action:
		s.ingestLogons(ctx, a, raw)
	case updates.SourceOf(module, action) != "":
		s.ingestUpdates(ctx, a, updates.SourceOf(module, action), raw)
	}
}

// ingestInventory stores an inventory result and records what changed.
// Errors are logged: the job or policy result itself is already stored.
func (s *Server) ingestInventory(ctx context.Context, a store.Agent, raw []byte) {
	inv, err := inventory.Parse(raw)
	if err != nil {
		s.log.Warn("invalid inventory", "agent", a.ID, "err", err)
		return
	}
	// The agent's clock is not trusted to be ahead of the console's.
	if now := s.now(); inv.CollectedAt.After(now.Add(5 * time.Minute)) {
		inv.CollectedAt = now
	}
	var old *inventory.Inventory
	if prev, err := s.store.GetInventory(ctx, a.TenantID, a.ID); err == nil {
		old, _ = inventory.Parse(prev.Data)
	} else if !errors.Is(err, store.ErrNotFound) {
		s.log.Error("load inventory", "agent", a.ID, "err", err)
		return
	}
	data, err := json.Marshal(inv)
	if err != nil {
		s.log.Error("encode inventory", "err", err)
		return
	}
	var changes []store.InventoryChange
	for _, c := range inventory.Diff(old, inv) {
		changes = append(changes, store.InventoryChange{At: inv.CollectedAt, Kind: c.Kind, Detail: c.Detail})
	}
	rec := store.Inventory{TenantID: a.TenantID, AgentID: a.ID, Data: data, Summary: store.InventorySummary{
		CollectedAt: inv.CollectedAt, Manufacturer: inv.System.Manufacturer, Model: inv.System.Model,
		Serial: inv.System.Serial, LoggedOnUser: inv.OS.LoggedOnUser, SupremoID: inv.RemoteAccess.SupremoID,
		AnyDeskID: inv.RemoteAccess.AnyDeskID, TeamViewerID: inv.RemoteAccess.TeamViewerID, IPv4: inv.IPv4()}}
	switch err := s.store.PutInventory(ctx, rec, changes); {
	case err == nil:
		s.log.Info("inventory stored", "agent", a.ID, "software", len(inv.Software), "changes", len(changes))
	case errors.Is(err, store.ErrStaleInventory):
		s.log.Info("older inventory ignored", "agent", a.ID)
	default:
		s.log.Error("store inventory", "agent", a.ID, "err", err)
	}
}

// ingestUpdates stores a winupdate or winget report.
func (s *Server) ingestUpdates(ctx context.Context, a store.Agent, source string, raw []byte) {
	now := s.now()
	st := store.UpdateStatus{TenantID: a.TenantID, AgentID: a.ID, Source: source, ManagedBy: "none"}
	var data any
	switch source {
	case updates.SourceWindows:
		r, err := updates.ParseWindows(raw, now)
		if err != nil {
			s.log.Warn("invalid windows update report", "agent", a.ID, "err", err)
			return
		}
		sum := r.Summarize(now)
		st.ScannedAt, st.ManagedBy, data = r.ScannedAt, r.ManagedBy, r
		st.Important, st.Other, st.OldestDays, st.Behind = sum.Important, sum.Other, sum.OldestDays, sum.Behind
		st.Reboot, st.RebootSince = sum.Reboot, sum.RebootSince
	case updates.SourceWinget:
		r, err := updates.ParseWinget(raw, now)
		if err != nil {
			s.log.Warn("invalid winget report", "agent", a.ID, "err", err)
			return
		}
		st.ScannedAt, st.ThirdParty, data = r.ScannedAt, len(r.Upgrades), r
	default:
		return
	}
	b, err := json.Marshal(data)
	if err != nil {
		s.log.Error("encode update report", "err", err)
		return
	}
	st.Data = b
	switch err := s.store.PutUpdateStatus(ctx, st); {
	case err == nil, errors.Is(err, store.ErrStaleReport):
	default:
		s.log.Error("store update report", "agent", a.ID, "err", err)
	}
}
