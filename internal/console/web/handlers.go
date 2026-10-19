package web

import (
	"encoding/json"
	"errors"
	"github.com/stefanozanarini/open-rmm/internal/adinv"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/open-rmm/internal/console/jobreq"
	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/console/wingetcat"
	"github.com/stefanozanarini/open-rmm/internal/ids"
	"github.com/stefanozanarini/open-rmm/internal/inventory"
	"github.com/stefanozanarini/open-rmm/internal/modules"
)

// tenant returns the session's current tenant, checked against the tenants
// the operator may manage.
func tenantOf(r *http.Request) (string, bool) {
	sess := sessionFrom(r.Context())
	t := sess.data.Tenant
	return t, t != "" && slices.Contains(sess.data.Operator.Tenants, t)
}

func (s *Server) handleSelectTenant(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	t := r.PostFormValue("tenant")
	if !slices.Contains(sess.data.Operator.Tenants, t) {
		http.Error(w, "tenant non autorizzato", http.StatusForbidden)
		return
	}
	sess.data.Tenant = t
	if err := s.save(r.Context(), w, sess); err != nil {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, "/agents", http.StatusSeeOther)
}

// runnable is a module action that can run on an agent.
type runnable struct {
	Module, Version, Action, Description string
	AdHoc                                bool
}

type agentData struct {
	Agent    store.Agent
	Results  []resultView
	Jobs     []store.Job
	Actions  []runnable
	Commands []runnable // regular module actions
	Scripts  []runnable // ad-hoc script actions
	Online   bool
	Inv      *inventory.Inventory
	InvAt    time.Time
	Software []inventory.Software
	Changes  []store.InventoryChange
	Checks   []store.Check
	Alerts   []alertView
	Logons   []store.LogonEvent
	Updates  agentUpdates
	// Outdated maps installed application names to the newer version in
	// the winget catalog.
	Outdated map[string]string
	Notes    []store.Note
	AD       *adPlace // computer object in Active Directory
	// Return is where forms on this agent go back to; Panel is set when the
	// agent is shown in the bottom panel of the agent list.
	Return string
	Panel  bool
}

func (s *Server) handleAgent(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	id := r.PathValue("id")
	if !ok || !ids.IsUUID(id) {
		http.NotFound(w, r)
		return
	}
	d, err := s.agentDetails(r, t, id)
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, r, "agent", d.Agent.Host.Hostname, d)
}

// agentDetails loads everything shown about one agent.
func (s *Server) agentDetails(r *http.Request, t, id string) (*agentData, error) {
	a, err := s.store.GetAgent(r.Context(), t, id)
	if err != nil {
		return nil, err
	}
	jobs, err := s.store.ListJobs(r.Context(), t, id, 20)
	if err != nil {
		return nil, err
	}
	d := &agentData{Agent: a, Jobs: jobs, Online: s.online(a), Return: "/agents/" + id}
	switch inv, err := s.store.GetInventory(r.Context(), t, id); {
	case err == nil:
		if d.Inv, err = inventory.Parse(inv.Data); err != nil {
			s.log.Error("stored inventory unreadable", "agent", id, "err", err)
		} else {
			d.InvAt, d.Software = inv.ReceivedAt, d.Inv.VisibleSoftware()
		}
	case !errors.Is(err, store.ErrNotFound):
		return nil, err
	}
	if d.Changes, err = s.store.ListInventoryChanges(r.Context(), t, id, 100); err != nil {
		return nil, err
	}
	if d.Checks, err = s.store.ListChecks(r.Context(), t, id); err != nil {
		return nil, err
	}
	alerts, err := s.store.ListAlerts(r.Context(), t, id, true, 100)
	if err != nil {
		return nil, err
	}
	d.Alerts = s.alertViews(r, t, alerts)
	if d.Logons, err = s.store.ListLogonEvents(r.Context(), t, id, 100); err != nil {
		return nil, err
	}
	if d.Updates, err = s.agentUpdates(r, t, id); err != nil {
		return nil, err
	}
	if d.Notes, err = s.store.ListNotes(r.Context(), t, id, 100); err != nil {
		return nil, err
	}
	snaps, err := s.adSnapshots(r.Context(), t)
	if err != nil {
		return nil, err
	}
	if pl, ok := adPlaces(snaps)[adinv.HostKey(a.Host.Hostname)]; ok {
		d.AD = &pl
	}
	d.Outdated = map[string]string{}
	if d.Inv != nil {
		if apps, err := s.store.ListCatalogApps(r.Context(), t); err == nil {
			for _, app := range apps {
				for _, sw := range d.Inv.Software {
					if v := wingetcat.Installed([]inventory.Software{sw}, app.MatchName, app.ProductCodes); len(v) > 0 &&
						wingetcat.CompareVersions(v[0], app.DisplayVersion) < 0 {
						d.Outdated[sw.Name] = app.Version
					}
				}
			}
		}
	}
	if d.Results, err = s.policyResults(r, t, id); err != nil {
		return nil, err
	}
	if a.Status == store.AgentActive {
		if d.Actions, err = s.runnableOn(r, a); err != nil {
			return nil, err
		}
		for _, x := range d.Actions {
			if x.AdHoc {
				d.Scripts = append(d.Scripts, x)
			} else {
				d.Commands = append(d.Commands, x)
			}
		}
	}
	return d, nil
}

func (s *Server) runnableOn(r *http.Request, a store.Agent) ([]runnable, error) {
	mods, err := s.store.ListModules(r.Context())
	if err != nil {
		return nil, err
	}
	platform := a.Host.OS + "/" + a.Host.Arch
	var out []runnable
	for _, m := range mods {
		man, err := modules.ParseManifest(m.Manifest)
		if err != nil {
			continue
		}
		if _, ok := man.Entrypoints[platform]; !ok {
			continue
		}
		for name, act := range man.Actions {
			out = append(out, runnable{Module: man.ID, Version: man.Version, Action: name, Description: act.Description,
				AdHoc: man.HasCapability(modules.CapAdHocScript)})
		}
	}
	sortRunnables(out)
	return out, nil
}

func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	id := r.PathValue("id")
	if !ok || !ids.IsUUID(id) {
		http.NotFound(w, r)
		return
	}
	op := sessionFrom(r.Context()).data.Operator
	a, err := s.store.GetAgent(r.Context(), t, id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	switch err := s.store.ApproveAgent(r.Context(), t, id, "operator:"+op.Username, s.now()); {
	case errors.Is(err, store.ErrNotPending):
		s.flash(w, r, "L'agente non è in attesa di approvazione.", "/agents/"+id)
		return
	case err != nil:
		s.fail(w, err)
		return
	}
	s.audit(r.Context(), t, op, "agent.approved", id, map[string]any{"hostname": a.Host.Hostname, "machine_id": a.Host.MachineID})
	s.flash(w, r, "Agente "+a.Host.Hostname+" approvato.", "/agents/"+id)
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	id := r.PathValue("id")
	if !ok || !ids.IsUUID(id) {
		http.NotFound(w, r)
		return
	}
	op := sessionFrom(r.Context()).data.Operator
	a, err := s.store.GetAgent(r.Context(), t, id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := s.store.SetAgentStatus(r.Context(), t, id, store.AgentRevoked); err != nil {
		s.fail(w, err)
		return
	}
	s.audit(r.Context(), t, op, "agent.revoked", id, map[string]any{"hostname": a.Host.Hostname})
	s.flash(w, r, "Agente "+a.Host.Hostname+" revocato.", "/agents/"+id)
}

// handleRunJob validates the form and starts the step-up authentication that
// approves exactly this job.
func (s *Server) handleRunJob(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	id := r.PathValue("id")
	if !ok || !ids.IsUUID(id) {
		http.NotFound(w, r)
		return
	}
	back := "/agents/" + id
	a, err := s.store.GetAgent(r.Context(), t, id)
	if err != nil || a.Status != store.AgentActive {
		s.flash(w, r, "Solo gli agenti approvati possono ricevere comandi.", back)
		return
	}
	target := strings.Split(r.PostFormValue("target"), "|")
	if len(target) != 3 {
		s.flash(w, r, "Seleziona un'azione.", back)
		return
	}
	module, version, action := target[0], target[1], target[2]
	mod, err := s.store.GetModule(r.Context(), module, version)
	if err != nil {
		s.flash(w, r, "Modulo non trovato.", back)
		return
	}
	man, err := modules.ParseManifest(mod.Manifest)
	if err != nil {
		s.fail(w, err)
		return
	}
	if _, ok := man.Actions[action]; !ok {
		s.flash(w, r, "Azione non disponibile.", back)
		return
	}
	params := map[string]any{}
	if raw := strings.TrimSpace(r.PostFormValue("params")); raw != "" {
		if err := json.Unmarshal([]byte(raw), &params); err != nil {
			s.flash(w, r, "I parametri devono essere un oggetto JSON.", back)
			return
		}
	}
	if man.HasCapability(modules.CapAdHocScript) {
		script := r.PostFormValue("script")
		if strings.TrimSpace(script) == "" {
			s.flash(w, r, "Scrivi lo script da eseguire.", back)
			return
		}
		params["script"] = script
	}
	paramsJSON, err := json.Marshal(params)
	if err != nil {
		s.fail(w, err)
		return
	}
	ttlMin, err := strconv.Atoi(r.PostFormValue("ttl_minutes"))
	if err != nil || ttlMin < 5 || ttlMin > 24*60 {
		ttlMin = 60
	}
	req := &openrmmv1.JobRequest{
		TenantId: t, AgentId: id, Module: man.ID, ModuleVersion: man.Version, ModuleSha256: mod.ManifestSHA256,
		Action: action, ParamsJson: paramsJSON, TtlSeconds: int64(ttlMin) * 60, RequestNonce: jobreq.NewRequestNonce(),
	}
	if err := jobreq.Validate(req); err != nil {
		s.flash(w, r, "Richiesta non valida: "+err.Error(), back)
		return
	}
	s.startStepUp(w, r, sessionFrom(r.Context()), req, back)
}

type jobsData struct{ Jobs []store.Job }

func (s *Server) handleJobs(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, "nessun tenant", http.StatusForbidden)
		return
	}
	jobs, err := s.store.ListJobs(r.Context(), t, "", 200)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, r, "jobs", "Job", jobsData{Jobs: jobs})
}

type jobData struct {
	Job    store.Job
	Agent  store.Agent
	Result string
	Params string
	Output string // the script module's output, shown as text
}

func (d jobData) refresh() int {
	if d.Job.State.Final() {
		return 0
	}
	return 3
}

func pretty(raw []byte) string {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return string(raw)
	}
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

func (s *Server) handleJob(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	id := r.PathValue("id")
	if !ok || !ids.IsUUID(id) {
		http.NotFound(w, r)
		return
	}
	j, err := s.store.GetJob(r.Context(), t, id)
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	a, _ := s.store.GetAgent(r.Context(), t, j.AgentID)
	d := jobData{Job: j, Agent: a, Params: pretty(j.Params)}
	if len(j.Result) > 0 {
		var res struct {
			Output *string `json:"output"`
		}
		if json.Unmarshal(j.Result, &res) == nil && res.Output != nil {
			d.Output = *res.Output
		}
		d.Result = pretty(j.Result)
	}
	s.render(w, r, "job", "Job "+j.ID[:8], d)
}

type modulesData struct{ Modules []moduleView }

type moduleView struct {
	store.Module
	Platforms []string
	Actions   []string
	AdHoc     bool
}

func (s *Server) handleModules(w http.ResponseWriter, r *http.Request) {
	mods, err := s.store.ListModules(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	var d modulesData
	for _, m := range mods {
		v := moduleView{Module: m}
		if man, err := modules.ParseManifest(m.Manifest); err == nil {
			for p := range man.Entrypoints {
				v.Platforms = append(v.Platforms, p)
			}
			for a := range man.Actions {
				v.Actions = append(v.Actions, a)
			}
			sort.Strings(v.Platforms)
			sort.Strings(v.Actions)
			v.AdHoc = man.HasCapability(modules.CapAdHocScript)
		}
		d.Modules = append(d.Modules, v)
	}
	s.render(w, r, "modules", "Moduli", d)
}

type tokensData struct {
	Tokens []store.EnrollmentToken
	New    string
	NewTok *store.EnrollmentToken
	Now    time.Time
}

func (s *Server) handleTokens(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, "nessun tenant", http.StatusForbidden)
		return
	}
	toks, err := s.store.ListEnrollmentTokens(r.Context(), t)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, r, "tokens", "Token di registrazione", tokensData{Tokens: toks, Now: s.now()})
}

func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, "nessun tenant", http.StatusForbidden)
		return
	}
	maxUses, err := strconv.Atoi(r.PostFormValue("max_uses"))
	if err != nil || maxUses < 1 || maxUses > 100000 {
		s.flash(w, r, "Numero di utilizzi non valido (1-100000).", "/tokens")
		return
	}
	days, err := strconv.Atoi(r.PostFormValue("days"))
	if err != nil || days < 1 || days > 90 {
		s.flash(w, r, "Validità non valida (1-90 giorni).", "/tokens")
		return
	}
	desc := strings.TrimSpace(r.PostFormValue("description"))
	if len(desc) > 200 {
		desc = desc[:200]
	}
	op := sessionFrom(r.Context()).data.Operator
	secret := ids.NewSecret(32)
	tok := store.EnrollmentToken{ID: ids.NewUUID(), TenantID: t, Description: desc, MaxUses: maxUses,
		ExpiresAt: s.now().Add(time.Duration(days) * 24 * time.Hour), AutoApprove: r.PostFormValue("auto_approve") == "on"}
	if err := s.store.CreateEnrollmentToken(r.Context(), tok, store.HashToken(secret)); err != nil {
		s.fail(w, err)
		return
	}
	s.audit(r.Context(), t, op, "enrollment_token.created", tok.ID, map[string]any{
		"max_uses": tok.MaxUses, "expires_at": tok.ExpiresAt.UTC().Format(time.RFC3339),
		"description": tok.Description, "auto_approve": tok.AutoApprove})
	toks, err := s.store.ListEnrollmentTokens(r.Context(), t)
	if err != nil {
		s.fail(w, err)
		return
	}
	// The secret is rendered once, in this response only.
	s.render(w, r, "tokens", "Token di registrazione", tokensData{Tokens: toks, New: secret, NewTok: &tok, Now: s.now()})
}

type auditData struct{ Events []auditView }

type auditView struct {
	Seq        int64
	OccurredAt time.Time
	Actor      string
	Action     string
	Target     string
	Details    string
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, "nessun tenant", http.StatusForbidden)
		return
	}
	events, err := s.store.ListAudit(r.Context(), t)
	if err != nil {
		s.fail(w, err)
		return
	}
	var d auditData
	// Newest first, at most 500.
	for i := len(events) - 1; i >= 0 && len(d.Events) < 500; i-- {
		e := events[i]
		det, _ := json.Marshal(e.Details)
		d.Events = append(d.Events, auditView{Seq: e.Seq, OccurredAt: e.OccurredAt, Actor: e.Actor, Action: e.Action,
			Target: e.Target, Details: string(det)})
	}
	s.render(w, r, "audit", "Registro attività", d)
}

type targetView struct {
	store.ReleaseTarget
	Done, Total int
}

type updatesData struct {
	Targets  []targetView
	Releases []store.Release
	Problems []store.Agent
}

func (s *Server) handleUpdates(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, "nessun tenant", http.StatusForbidden)
		return
	}
	targets, err := s.store.ListReleaseTargets(r.Context(), t)
	if err != nil {
		s.fail(w, err)
		return
	}
	rels, err := s.store.ListReleases(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	agents, err := s.store.ListAgents(r.Context(), t)
	if err != nil {
		s.fail(w, err)
		return
	}
	d := updatesData{Releases: rels}
	for _, tg := range targets {
		v := targetView{ReleaseTarget: tg}
		for _, a := range agents {
			if a.Status == store.AgentActive && a.UpdateRing == tg.Ring && a.Host.OS+"/"+a.Host.Arch == tg.Platform {
				v.Total++
				if a.Host.AgentVersion == tg.Version {
					v.Done++
				}
			}
		}
		d.Targets = append(d.Targets, v)
	}
	for _, a := range agents {
		if a.Update.State == "rolled_back" || a.Update.State == "rejected" {
			d.Problems = append(d.Problems, a)
		}
	}
	s.render(w, r, "updates", "Versioni dell'agente", d)
}

type resultView struct {
	store.PolicyResult
	Policy string
	Pretty string
}

func (s *Server) policyResults(r *http.Request, tenant, agent string) ([]resultView, error) {
	rs, err := s.store.ListPolicyResults(r.Context(), tenant, agent)
	if err != nil {
		return nil, err
	}
	names := map[string]string{}
	if cur, err := s.store.CurrentPolicies(r.Context(), tenant); err == nil {
		for _, p := range cur {
			names[p.ID] = p.Name
		}
	}
	out := make([]resultView, 0, len(rs))
	for _, x := range rs {
		v := resultView{PolicyResult: x, Policy: names[x.PolicyID]}
		if v.Policy == "" {
			v.Policy = "(eliminata)"
		}
		if len(x.Result) > 0 {
			v.Pretty = pretty(x.Result)
		}
		out = append(out, v)
	}
	return out, nil
}

func sortRunnables(out []runnable) {
	sort.Slice(out, func(i, j int) bool {
		return out[i].Module+out[i].Version+out[i].Action < out[j].Module+out[j].Version+out[j].Action
	})
}
