package web

import (
	"html/template"
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
		http.Error(w, s.T(r, "tenant non autorizzato"), http.StatusForbidden)
		return
	}
	sess.data.Tenant, sess.data.Link = t, ""
	if err := s.save(r.Context(), w, sess); err != nil {
		s.fail(w, r, err)
		return
	}
	http.Redirect(w, r, "/agents", http.StatusSeeOther)
}

// runnable is a module action that can run on an agent.
type runnable struct {
	Module, Version, Action, Description string
	AdHoc                                bool
	// Fields of the action's parameters; Known is false when the module
	// has no description (the form shows a JSON field).
	Fields []paramField
	Known  bool
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
	Site     agentSite
	Shell    bool // an interactive shell can be opened
	// Packages of the library, to install from the agent page.
	Packages []store.Package
	// ADReader: this agent reads Active Directory every 24 hours.
	ADReader bool
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
		s.fail(w, r, err)
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
	var ipv4 []string
	if d.Inv != nil {
		ipv4 = d.Inv.IPv4()
	}
	if d.Site, err = s.agentSite(r, t, a, ipv4); err != nil {
		return nil, err
	}
	if d.Packages, err = s.store.ListPackages(r.Context(), t); err != nil {
		return nil, err
	}
	if st, err := s.store.GetSettings(r.Context(), t); err == nil {
		d.ADReader = slices.Contains(st.ADReaders, id)
	}
	snaps, err := s.adSnapshots(r.Context(), t)
	if err != nil {
		return nil, err
	}
	if pl, ok := adPlaces(snaps)[adinv.HostKey(a.Host.Hostname)]; ok {
		d.AD = &pl
	}
	if s.shell != nil && a.Status == store.AgentActive {
		_, d.Shell = s.shellModuleFor(r, a)
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
	// Only the newest version of each module: older ones stay published
	// for the agents that still pin them, but are not offered.
	newest := map[string]string{}
	for _, m := range mods {
		if cur, ok := newest[m.ID]; !ok || wingetcat.CompareVersions(m.Version, cur) > 0 {
			newest[m.ID] = m.Version
		}
	}
	var out []runnable
	for _, m := range mods {
		if m.Version != newest[m.ID] {
			continue
		}
		man, err := modules.ParseManifest(m.Manifest)
		if err != nil {
			continue
		}
		if _, ok := man.Entrypoints[platform]; !ok || man.HasCapability(modules.CapInteractiveShell) {
			continue // shells open from their own button, one agent at a time
		}
		if man.ID == softwareModule {
			continue // installs and removals have their own forms (package, installed application)
		}
		sch, known := s.paramSchema(m, man)
		for name, act := range man.Actions {
			x := runnable{Module: man.ID, Version: man.Version, Action: name, Description: act.Description,
				AdHoc: man.HasCapability(modules.CapAdHocScript)}
			if specs, ok := sch[name]; known && ok {
				x.Known, x.Fields = true, paramFields(s.lang(r), specs)
			}
			out = append(out, x)
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
		s.flash(w, r, s.T(r, "L'agente non è in attesa di approvazione."), "/agents/"+id)
		return
	case err != nil:
		s.fail(w, r, err)
		return
	}
	s.audit(r.Context(), t, op, "agent.approved", id, map[string]any{"hostname": a.Host.Hostname, "machine_id": a.Host.MachineID})
	s.flash(w, r, s.Tf(r, "Agente %s approvato.", a.Host.Hostname), "/agents/"+id)
}

// handleApproveMany approves, or turns down (revokes), the pending agents
// selected in the list.
func (s *Server) handleApproveMany(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, s.T(r, "richiesta non valida"), http.StatusBadRequest)
		return
	}
	op := sessionFrom(r.Context()).data.Operator
	approve := r.PostFormValue("do") != "revoke"
	selected := r.PostForm["agent"]
	if len(selected) == 0 {
		s.flash(w, r, s.T(r, "Seleziona almeno un agente."), "/agents")
		return
	}
	if len(selected) > 500 {
		http.Error(w, s.T(r, "richiesta non valida"), http.StatusBadRequest)
		return
	}
	done := 0
	for _, id := range selected {
		if !ids.IsUUID(id) {
			continue
		}
		a, err := s.store.GetAgent(r.Context(), t, id)
		if err != nil || a.Status != store.AgentPending {
			continue
		}
		if approve {
			switch err := s.store.ApproveAgent(r.Context(), t, id, "operator:"+op.Username, s.now()); {
			case errors.Is(err, store.ErrNotPending):
				continue
			case err != nil:
				s.fail(w, r, err)
				return
			}
			s.audit(r.Context(), t, op, "agent.approved", id, map[string]any{"hostname": a.Host.Hostname, "machine_id": a.Host.MachineID})
		} else {
			if err := s.store.SetAgentStatus(r.Context(), t, id, store.AgentRevoked); err != nil {
				s.fail(w, r, err)
				return
			}
			s.audit(r.Context(), t, op, "agent.revoked", id, map[string]any{"hostname": a.Host.Hostname})
		}
		done++
	}
	if approve {
		s.flash(w, r, s.Tf(r, "%d agenti approvati.", done), "/agents")
	} else {
		s.flash(w, r, s.Tf(r, "%d agenti rifiutati e revocati.", done), "/agents")
	}
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
		s.fail(w, r, err)
		return
	}
	s.audit(r.Context(), t, op, "agent.revoked", id, map[string]any{"hostname": a.Host.Hostname})
	s.flash(w, r, s.Tf(r, "Agente %s revocato.", a.Host.Hostname), "/agents/"+id)
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
		s.flash(w, r, s.T(r, "Solo gli agenti approvati possono ricevere comandi."), back)
		return
	}
	target := strings.Split(r.PostFormValue("target"), "|")
	if len(target) != 3 {
		s.flash(w, r, s.T(r, "Seleziona un'azione."), back)
		return
	}
	module, version, action := target[0], target[1], target[2]
	mod, err := s.store.GetModule(r.Context(), module, version)
	if err != nil {
		s.flash(w, r, s.T(r, "Modulo non trovato."), back)
		return
	}
	man, err := modules.ParseManifest(mod.Manifest)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if _, ok := man.Actions[action]; !ok || man.HasCapability(modules.CapInteractiveShell) {
		s.flash(w, r, s.T(r, "Azione non disponibile."), back)
		return
	}
	params, msg := s.jobParams(r, mod, man, action)
	if msg != "" {
		s.flash(w, r, msg, back)
		return
	}
	if man.HasCapability(modules.CapAdHocScript) {
		script := r.PostFormValue("script")
		if strings.TrimSpace(script) == "" {
			s.flash(w, r, s.T(r, "Scrivi lo script da eseguire."), back)
			return
		}
		params["script"] = script
	}
	paramsJSON, err := json.Marshal(params)
	if err != nil {
		s.fail(w, r, err)
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
		s.flash(w, r, s.Tf(r, "Richiesta non valida: %v", err), back)
		return
	}
	s.startStepUp(w, r, sessionFrom(r.Context()), req, back)
}

type jobsData struct{ Jobs []store.Job }

func (s *Server) handleJobs(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, s.T(r, "nessun tenant"), http.StatusForbidden)
		return
	}
	jobs, err := s.store.ListJobs(r.Context(), t, "", 200)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.render(w, r, "jobs", s.T(r, "Job"), jobsData{Jobs: jobs})
}

type jobData struct {
	Job    store.Job
	Agent  store.Agent
	Result string // JSON, folded
	Params string
	Output string // the script module's output, shown as text
	// Outcome is a sentence for the result; ResultView and ParamsView the
	// fields as labelled values and tables.
	Outcome    string
	ResultView template.HTML
	ParamsView template.HTML
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
		s.fail(w, r, err)
		return
	}
	a, _ := s.store.GetAgent(r.Context(), t, j.AgentID)
	lang := s.lang(r)
	d := jobData{Job: j, Agent: a, Params: pretty(j.Params), ParamsView: renderResult(lang, j.Params)}
	if len(j.Result) > 0 {
		var res struct {
			Output *string `json:"output"`
		}
		if json.Unmarshal(j.Result, &res) == nil && res.Output != nil {
			d.Output = *res.Output
		}
		d.Result = pretty(j.Result)
		d.ResultView = renderResult(lang, j.Result, "output")
		var fields map[string]any
		if json.Unmarshal(j.Result, &fields) == nil && j.State == store.JobSucceeded {
			d.Outcome = jobOutcome(lang, j.Module, j.Action, fields)
		}
	}
	s.render(w, r, "job", "Job "+j.ID[:8], d)
}

type modulesData struct {
	Modules []moduleView
	Publish publishView
}

type moduleView struct {
	store.Module
	Platforms []string
	Actions   []string
	AdHoc     bool
}

func (s *Server) handleModules(w http.ResponseWriter, r *http.Request) {
	mods, err := s.store.ListModules(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d := modulesData{Publish: s.publishData(r, modulesKind)}
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
	s.render(w, r, "modules", s.T(r, "Moduli"), d)
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
		http.Error(w, s.T(r, "nessun tenant"), http.StatusForbidden)
		return
	}
	toks, err := s.store.ListEnrollmentTokens(r.Context(), t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.render(w, r, "tokens", s.T(r, "Token di registrazione"), tokensData{Tokens: toks, Now: s.now()})
}

func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, s.T(r, "nessun tenant"), http.StatusForbidden)
		return
	}
	maxUses, err := strconv.Atoi(r.PostFormValue("max_uses"))
	if err != nil || maxUses < 1 || maxUses > 100000 {
		s.flash(w, r, s.T(r, "Numero di utilizzi non valido (1-100000)."), "/tokens")
		return
	}
	days, err := strconv.Atoi(r.PostFormValue("days"))
	if err != nil || days < 1 || days > 90 {
		s.flash(w, r, s.T(r, "Validità non valida (1-90 giorni)."), "/tokens")
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
		s.fail(w, r, err)
		return
	}
	s.audit(r.Context(), t, op, "enrollment_token.created", tok.ID, map[string]any{
		"max_uses": tok.MaxUses, "expires_at": tok.ExpiresAt.UTC().Format(time.RFC3339),
		"description": tok.Description, "auto_approve": tok.AutoApprove})
	toks, err := s.store.ListEnrollmentTokens(r.Context(), t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	// The secret is rendered once, in this response only.
	s.render(w, r, "tokens", s.T(r, "Token di registrazione"), tokensData{Tokens: toks, New: secret, NewTok: &tok, Now: s.now()})
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
		http.Error(w, s.T(r, "nessun tenant"), http.StatusForbidden)
		return
	}
	events, err := s.store.ListAudit(r.Context(), t)
	if err != nil {
		s.fail(w, r, err)
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
	s.render(w, r, "audit", s.T(r, "Registro attività"), d)
}

type targetView struct {
	store.ReleaseTarget
	Done, Total int
}

type updatesData struct {
	Targets  []targetView
	Releases []store.Release
	Problems []store.Agent
	Publish  publishView
	// AutoPilot: new releases become the pilot ring's target at once.
	AutoPilot bool
}

func (s *Server) handleUpdates(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, s.T(r, "nessun tenant"), http.StatusForbidden)
		return
	}
	targets, err := s.store.ListReleaseTargets(r.Context(), t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	rels, err := s.store.ListReleases(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	agents, err := s.store.ListAgents(r.Context(), t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d := updatesData{Releases: rels, Publish: s.publishData(r, releasesKind)}
	if st, err := s.store.GetSettings(r.Context(), t); err == nil {
		d.AutoPilot = !st.PilotManual
	}
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
	s.render(w, r, "updates", s.T(r, "Versioni dell'agente"), d)
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
			v.Policy = s.T(r, "(eliminata)")
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

// handleSetTarget sets the version a ring updates to. The release is signed
// already and agents refuse anything not newer than themselves, so it needs
// the Admin role but no new sign-in; it is audited.
func (s *Server) handleSetTarget(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, s.T(r, "nessun tenant"), http.StatusForbidden)
		return
	}
	ring, platform, version := r.PostFormValue("ring"), r.PostFormValue("platform"), r.PostFormValue("version")
	if !store.ValidRing(ring) {
		http.NotFound(w, r)
		return
	}
	op := sessionFrom(r.Context()).data.Operator
	err := s.store.SetReleaseTarget(r.Context(), store.ReleaseTarget{TenantID: t, Ring: ring, Platform: platform, Version: version,
		UpdatedBy: "operator:" + op.Username})
	if errors.Is(err, store.ErrNotFound) {
		s.flash(w, r, s.T(r, "Versione non disponibile."), "/updates")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r.Context(), t, op, "release.target_set", ring, map[string]any{"platform": platform, "version": version})
	s.flash(w, r, s.Tf(r, "Gli agenti dell'anello %s su %s si aggiorneranno alla %s.", ring, platform, version), "/updates")
}

// handleAutoPilot turns the automatic pilot target on or off.
func (s *Server) handleAutoPilot(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, s.T(r, "nessun tenant"), http.StatusForbidden)
		return
	}
	cur, err := s.store.GetSettings(r.Context(), t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	cur.PilotManual = r.PostFormValue("auto") != "1"
	op := sessionFrom(r.Context()).data.Operator
	if err := s.store.PutSettings(r.Context(), t, cur, "operator:"+op.Username); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r.Context(), t, op, "settings.auto_pilot", "", map[string]any{"auto": !cur.PilotManual})
	s.flash(w, r, s.T(r, "Impostazione salvata."), "/updates")
}

// handleRevokeToken revokes an enrollment token of the tenant: no new agent
// can enroll with it; agents already enrolled are not affected.
func (s *Server) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	id := r.PathValue("id")
	if !ok || !ids.IsUUID(id) {
		http.NotFound(w, r)
		return
	}
	tokens, err := s.store.ListEnrollmentTokens(r.Context(), t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !slices.ContainsFunc(tokens, func(k store.EnrollmentToken) bool { return k.ID == id }) {
		http.NotFound(w, r)
		return
	}
	if err := s.store.RevokeEnrollmentToken(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r.Context(), t, sessionFrom(r.Context()).data.Operator, "token.revoked", id, nil)
	s.flash(w, r, s.T(r, "Token revocato: nessun nuovo agente può registrarsi con esso."), safeReturn(r.PostFormValue("return"), "/tokens"))
}
