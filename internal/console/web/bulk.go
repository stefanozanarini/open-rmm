package web

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/open-rmm/internal/console/jobreq"
	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/ids"
	"github.com/stefanozanarini/open-rmm/internal/modules"
)

type bulkData struct {
	Agents   []store.Agent
	Commands []runnable
	Scripts  []runnable
	Packages []store.Package
}

// selectedAgents returns the active agents listed in the "agent" values.
func (s *Server) selectedAgents(r *http.Request, t string, values []string) ([]store.Agent, string) {
	var out []store.Agent
	seen := map[string]bool{}
	for _, id := range values {
		if !ids.IsUUID(id) || seen[id] {
			continue
		}
		seen[id] = true
		a, err := s.store.GetAgent(r.Context(), t, id)
		if err != nil || a.Status != store.AgentActive {
			return nil, s.T(r, "Solo gli agenti approvati possono ricevere comandi.")
		}
		out = append(out, a)
	}
	if len(out) == 0 || len(out) > jobreq.MaxAgents {
		return nil, s.Tf(r, "Seleziona da 1 a %d agenti approvati.", jobreq.MaxAgents)
	}
	return out, ""
}

func (s *Server) handleBulkForm(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, s.T(r, "nessun tenant"), http.StatusForbidden)
		return
	}
	agents, msg := s.selectedAgents(r, t, r.URL.Query()["agent"])
	if msg != "" {
		s.flash(w, r, msg, "/agents")
		return
	}
	d := bulkData{Agents: agents}
	// Actions available on every selected agent's platform.
	count := map[string]int{}
	byKey := map[string]runnable{}
	platforms := map[string]bool{}
	for _, a := range agents {
		p := a.Host.OS + "/" + a.Host.Arch
		if platforms[p] {
			continue
		}
		platforms[p] = true
		acts, err := s.runnableOn(r, a)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		for _, x := range acts {
			k := x.Module + "|" + x.Version + "|" + x.Action
			count[k]++
			byKey[k] = x
		}
	}
	for k, n := range count {
		if n != len(platforms) {
			continue
		}
		if x := byKey[k]; x.AdHoc {
			d.Scripts = append(d.Scripts, x)
		} else {
			d.Commands = append(d.Commands, x)
		}
	}
	sortRunnables(d.Commands)
	sortRunnables(d.Scripts)
	var err error
	if d.Packages, err = s.store.ListPackages(r.Context(), t); err != nil {
		s.fail(w, r, err)
		return
	}
	s.render(w, r, "bulk", s.Tf(r, "Azioni su %d agenti", len(agents)), d)
}

func (s *Server) handleBulkJobs(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, s.T(r, "nessun tenant"), http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, s.T(r, "richiesta non valida"), http.StatusBadRequest)
		return
	}
	agents, msg := s.selectedAgents(r, t, r.PostForm["agent"])
	back := "/agents"
	if msg != "" {
		s.flash(w, r, msg, back)
		return
	}
	var targets []string
	for _, a := range agents {
		targets = append(targets, a.ID)
	}
	back = "/agents/bulk?" + url.Values{"agent": targets}.Encode()
	if sha := r.PostFormValue("package"); sha != "" {
		if !shaHexRe.MatchString(sha) {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, "/packages/"+sha+"/deploy?"+url.Values{"agent": targets}.Encode(), http.StatusSeeOther)
		return
	}
	target := strings.Split(r.PostFormValue("target"), "|")
	if len(target) != 3 {
		s.flash(w, r, s.T(r, "Seleziona un'azione."), back)
		return
	}
	mod, err := s.store.GetModule(r.Context(), target[0], target[1])
	if err != nil {
		s.flash(w, r, s.T(r, "Modulo non trovato."), back)
		return
	}
	man, err := modules.ParseManifest(mod.Manifest)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if _, ok := man.Actions[target[2]]; !ok || man.HasCapability(modules.CapInteractiveShell) {
		s.flash(w, r, s.T(r, "Azione non disponibile."), back)
		return
	}
	params := map[string]any{}
	if raw := strings.TrimSpace(r.PostFormValue("params")); raw != "" {
		if err := json.Unmarshal([]byte(raw), &params); err != nil {
			s.flash(w, r, s.T(r, "I parametri devono essere un oggetto JSON."), back)
			return
		}
	}
	if man.HasCapability(modules.CapAdHocScript) {
		script := r.PostFormValue("script")
		if strings.TrimSpace(script) == "" {
			s.flash(w, r, s.T(r, "Scrivi lo script da eseguire."), back)
			return
		}
		params["script"] = script
	}
	raw, err := json.Marshal(params)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	req := &openrmmv1.JobRequest{TenantId: t, Module: man.ID, ModuleVersion: man.Version, ModuleSha256: mod.ManifestSHA256,
		Action: target[2], ParamsJson: raw, TtlSeconds: ttlFrom(r), RequestNonce: jobreq.NewRequestNonce()}
	if len(targets) == 1 {
		req.AgentId = targets[0]
	} else {
		req.AgentIds = targets
	}
	if err := jobreq.Validate(req); err != nil {
		s.flash(w, r, s.Tf(r, "Richiesta non valida: %v", err), back)
		return
	}
	s.startStepUp(w, r, sessionFrom(r.Context()), req, back)
}
