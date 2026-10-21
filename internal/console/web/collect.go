package web

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/open-rmm/internal/adinv"
	"github.com/stefanozanarini/open-rmm/internal/console/audit"
	"github.com/stefanozanarini/open-rmm/internal/console/jobreq"
	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/console/wingetcat"
	"github.com/stefanozanarini/open-rmm/internal/ids"
	"github.com/stefanozanarini/open-rmm/internal/policy"
	"github.com/stefanozanarini/open-rmm/internal/updates"
)

// On-demand collections: an operator refreshes what the automatic
// collection gathers (update scan, inventory...) without waiting for the
// next run. They are read-only, so the signer signs them without a new
// sign-in, exactly like the automatic collection (signer.SignCollect).

// latestModule returns the newest published version of a module.
func (s *Server) latestModule(ctx context.Context, id string) (store.Module, bool, error) {
	mods, err := s.store.ListModules(ctx)
	if err != nil {
		return store.Module{}, false, err
	}
	var best store.Module
	found := false
	for _, m := range mods {
		if m.ID == id && (!found || wingetcat.CompareVersions(m.Version, best.Version) > 0) {
			best, found = m, true
		}
	}
	return best, found, nil
}

func (s *Server) handleCollect(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	id := r.PathValue("id")
	if !ok || !ids.IsUUID(id) {
		http.NotFound(w, r)
		return
	}
	back := r.PostFormValue("return")
	if !strings.HasPrefix(back, "/agents") {
		back = "/agents/" + id
	}
	module, action := r.PostFormValue("module"), r.PostFormValue("action")
	if !policy.IsCollection(module, action) {
		http.NotFound(w, r)
		return
	}
	a, err := s.store.GetAgent(r.Context(), t, id)
	if err != nil || a.Status != store.AgentActive {
		s.flash(w, r, s.T(r, "Solo gli agenti approvati possono ricevere comandi."), back)
		return
	}
	op := sessionFrom(r.Context()).data.Operator
	msg, err := s.startCollect(r.Context(), t, id, module, action, op)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if msg != "" {
		s.flash(w, r, msg, back)
		return
	}
	s.flash(w, r, s.T(r, "Raccolta avviata: i risultati arrivano tra qualche minuto."), back)
}

// startCollect has the signer sign a collection for one agent and queues
// it. op is nil for the console's own schedules. msg is for the operator.
func (s *Server) startCollect(ctx context.Context, t, agent, module, action string, op *Operator) (msg string, err error) {
	mod, found, err := s.latestModule(ctx, module)
	if err != nil {
		return "", err
	}
	if !found {
		return trf("it", "Il modulo %s non è pubblicato.", module), nil
	}
	req := &openrmmv1.JobRequest{TenantId: t, AgentId: agent, Module: mod.ID, ModuleVersion: mod.Version, ModuleSha256: mod.ManifestSHA256,
		Action: action, ParamsJson: []byte("{}"), TtlSeconds: int64(time.Hour / time.Second), RequestNonce: jobreq.NewRequestNonce()}
	sctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	resp, err := s.signer.SignCollect(sctx, &openrmmv1.SignCollectRequest{Request: req})
	if err != nil {
		return "Il servizio di firma ha rifiutato il comando: " + grpcMessage(err), nil
	}
	by := "console"
	if op != nil {
		by = "operator:" + op.Username
	}
	for _, sj := range resp.GetJobs() {
		j := store.Job{TenantID: t, ID: sj.GetJobId(), AgentID: sj.GetAgentId(), Module: mod.ID, ModuleVersion: mod.Version,
			Action: action, Params: req.GetParamsJson(), Envelope: sj.GetEnvelope(), CreatedBy: by,
			ExpiresAt: time.Unix(resp.GetExpiresUnix(), 0)}
		if err := s.store.CreateJob(ctx, j); err != nil {
			return "", err
		}
		details := map[string]any{"agent": agent, "module": mod.ID, "version": mod.Version, "action": action,
			"params": json.RawMessage(j.Params), "approved_by": resp.GetOperator()}
		if op != nil {
			s.audit(ctx, t, op, "job.created", j.ID, details)
		} else if _, err := s.store.AppendAudit(ctx, audit.Event{TenantID: t, Actor: "console", Action: "job.created",
			Target: j.ID, OccurredAt: s.now(), Details: details}); err != nil {
			s.log.Error("audit append failed", "err", err)
		}
	}
	return "", nil
}

// RunADReaders has the servers chosen to read Active Directory do so when
// they have not in the last 23 hours. Called hourly.
func (s *Server) RunADReaders(ctx context.Context) {
	if s.signer == nil {
		return
	}
	tenants, err := s.store.ListTenants(ctx)
	if err != nil {
		s.log.Error("active directory readers", "err", err)
		return
	}
	for _, t := range tenants {
		st, err := s.store.GetSettings(ctx, t.ID)
		if err != nil {
			continue
		}
		for _, agent := range st.ADReaders {
			a, err := s.store.GetAgent(ctx, t.ID, agent)
			if err != nil || a.Status != store.AgentActive {
				continue
			}
			jobs, err := s.store.ListJobs(ctx, t.ID, agent, 200)
			if err != nil {
				continue
			}
			recent := false
			for _, j := range jobs {
				recent = recent || (j.Module == adinv.ModuleID && s.now().Sub(j.CreatedAt) < 23*time.Hour)
			}
			if recent {
				continue
			}
			if msg, err := s.startCollect(ctx, t.ID, agent, adinv.ModuleID, adinv.Action, nil); err != nil || msg != "" {
				s.log.Warn("active directory reader", "agent", agent, "err", err, "msg", msg)
			}
		}
	}
}

// handleADReader marks a server as an Active Directory reader, or not.
func (s *Server) handleADReader(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	id := r.PathValue("id")
	if !ok || !ids.IsUUID(id) {
		http.NotFound(w, r)
		return
	}
	back := r.PostFormValue("return")
	if !strings.HasPrefix(back, "/agents") {
		back = "/agents/" + id
	}
	if _, err := s.store.GetAgent(r.Context(), t, id); err != nil {
		http.NotFound(w, r)
		return
	}
	cur, err := s.store.GetSettings(r.Context(), t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	on := r.PostFormValue("on") == "1"
	var next []string
	for _, a := range cur.ADReaders {
		if a != id {
			next = append(next, a)
		}
	}
	if on {
		next = append(next, id)
	}
	cur.ADReaders = next
	op := sessionFrom(r.Context()).data.Operator
	if err := s.store.PutSettings(r.Context(), t, cur, "operator:"+op.Username); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r.Context(), t, op, "settings.ad_reader", id, map[string]any{"on": on})
	if on {
		if msg, err := s.startCollect(r.Context(), t, id, adinv.ModuleID, adinv.Action, op); err != nil || msg != "" {
			s.log.Warn("active directory reader", "agent", id, "err", err, "msg", msg)
		}
		s.flash(w, r, s.T(r, "Questo server legge Active Directory ogni 24 ore: la prima lettura è partita."), back)
		return
	}
	s.flash(w, r, s.T(r, "Questo server non legge più Active Directory."), back)
}

// handleSetRing moves agents to the pilot or broad update ring: the one in
// the path, or the "agent" values of a selection.
func (s *Server) handleSetRing(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	ring := r.PostFormValue("ring")
	agents := r.PostForm["agent"]
	if id := r.PathValue("id"); id != "" {
		agents = []string{id}
	}
	if !ok || !store.ValidRing(ring) || len(agents) == 0 || len(agents) > 1000 {
		http.NotFound(w, r)
		return
	}
	back := r.PostFormValue("return")
	if !strings.HasPrefix(back, "/agents") {
		back = "/agents"
		if len(agents) == 1 {
			back += "/" + agents[0]
		}
	}
	op := sessionFrom(r.Context()).data.Operator
	for _, id := range agents {
		if !ids.IsUUID(id) {
			continue
		}
		if err := s.store.SetAgentRing(r.Context(), t, id, ring); err != nil {
			s.fail(w, r, err)
			return
		}
		s.audit(r.Context(), t, op, "agent.ring_set", id, map[string]any{"ring": ring})
	}
	s.flash(w, r, s.Tf(r, "Anello aggiornamenti: %s.", ring), back)
}

// Restart checks: a pending reboot is reported by the Windows Update scan,
// which runs every 24 hours, so a restarted endpoint would show it until
// the next scan. For online agents with a reboot pending, the console scans
// again 10 minutes after a restart job ends (with the inventory, for the
// boot time), and every rebootRescanEvery otherwise, to notice restarts
// done outside the console.
const (
	rebootRescanAfterJob = 10 * time.Minute
	rebootRescanEvery    = 3 * time.Hour
)

// RunRebootRescans queues those scans. Called every 10 minutes.
func (s *Server) RunRebootRescans(ctx context.Context) {
	if s.signer == nil {
		return
	}
	tenants, err := s.store.ListTenants(ctx)
	if err != nil {
		s.log.Error("reboot rescans", "err", err)
		return
	}
	now := s.now()
	for _, t := range tenants {
		statuses, err := s.store.ListUpdateStatus(ctx, t.ID, "")
		if err != nil {
			continue
		}
		for _, st := range statuses {
			if st.Source != updates.SourceWindows || !st.Reboot {
				continue
			}
			a, err := s.store.GetAgent(ctx, t.ID, st.AgentID)
			if err != nil || a.Status != store.AgentActive || !s.online(a) {
				continue
			}
			jobs, err := s.store.ListJobs(ctx, t.ID, a.ID, 200)
			if err != nil {
				continue
			}
			var lastScan, rebooted time.Time
			for _, j := range jobs {
				switch {
				case j.Module == "winupdate" && j.Action == "scan" && j.CreatedAt.After(lastScan):
					lastScan = j.CreatedAt
				case j.Module == "reboot" && j.State == store.JobSucceeded && j.FinishedAt != nil && j.FinishedAt.After(rebooted):
					rebooted = *j.FinishedAt
				}
			}
			if lastScan.Before(st.ScannedAt) {
				lastScan = st.ScannedAt
			}
			afterJob := rebooted.After(lastScan) && now.Sub(rebooted) >= rebootRescanAfterJob
			if !afterJob && now.Sub(lastScan) < rebootRescanEvery {
				continue
			}
			collections := [][2]string{{"winupdate", "scan"}}
			if afterJob {
				collections = append(collections, [2]string{"inventory", "collect"})
			}
			for _, c := range collections {
				if msg, err := s.startCollect(ctx, t.ID, a.ID, c[0], c[1], nil); err != nil || msg != "" {
					s.log.Warn("reboot rescan", "agent", a.ID, "module", c[0], "err", err, "msg", msg)
				}
			}
		}
	}
}
