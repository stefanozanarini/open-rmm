package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"

	openrmmv1 "github.com/stefanozanarini/tempra-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/tempra-rmm/internal/console/jobreq"
	"github.com/stefanozanarini/tempra-rmm/internal/console/store"
	"github.com/stefanozanarini/tempra-rmm/internal/ids"
	"github.com/stefanozanarini/tempra-rmm/internal/modules"
)

type bulkData struct {
	Agents   []store.Agent
	Sites    []store.Site
	Commands []runnable
	Scripts  []runnable
	Packages []store.Package
	// Preset: the action opened with its parameters filled in (?action=
	// module.action&p.<name>=…), and why (?for=, e.g. a CVE).
	Preset, For string
	// Files: a file session can be opened on the selected agents.
	Files bool
	// Group: the agents are those of a group (?group=); Groups: the
	// computer groups the agents can be added to.
	Group  *store.Group
	Groups []store.Group
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
	values := r.URL.Query()["agent"]
	var group *store.Group
	if id := r.URL.Query().Get("group"); id != "" {
		g, err := s.findGroup(r, t, id)
		if errors.Is(err, store.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			s.fail(w, r, err)
			return
		}
		all, err := s.tenantAgents(r, t)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		values, group = activeIDs(groupAgents(g, all)), &g
		if len(values) == 0 {
			s.flash(w, r, s.T(r, "Il gruppo non ha computer approvati."), "/groups/"+g.ID)
			return
		}
	}
	agents, msg := s.selectedAgents(r, t, values)
	if msg != "" {
		s.flash(w, r, msg, "/agents")
		return
	}
	sites, err := s.store.ListSites(r.Context(), t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d := bulkData{Agents: agents, Sites: sites, Group: group}
	groups, err := s.visibleGroups(r, t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	for _, g := range groups {
		if g.Kind == store.GroupComputer {
			d.Groups = append(d.Groups, g)
		}
	}
	if _, man, ok := s.fileModule(r); ok && s.shell != nil {
		d.Files = true
		for _, a := range agents {
			if _, ok := man.Entrypoints[a.Host.OS+"/"+a.Host.Arch]; !ok || !filesAgent(a.Host.AgentVersion) {
				d.Files = false
			}
		}
	}
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
	q := r.URL.Query()
	if preset := q.Get("action"); preset != "" {
		for i := range d.Commands {
			c := &d.Commands[i]
			if c.Module+"."+c.Action != preset {
				continue
			}
			c.Open, d.Preset, d.For = true, preset, q.Get("for")
			for j := range c.Fields {
				if vals, ok := q["p."+c.Fields[j].Name]; ok {
					presetField(&c.Fields[j], vals)
				}
			}
		}
	}
	if d.Packages, err = s.store.ListPackages(r.Context(), t); err != nil {
		s.fail(w, r, err)
		return
	}
	title := s.Tf(r, "Azioni su %d agenti", len(agents))
	if group != nil {
		title = s.Tf(r, "Azioni sul gruppo %s (%d computer)", group.Name, len(agents))
	}
	s.render(w, r, "bulk", title, d)
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
	if _, ok := man.Actions[target[2]]; !ok || man.Interactive() {
		s.flash(w, r, s.T(r, "Azione non disponibile."), back)
		return
	}
	params, msg := s.jobParams(r, mod, man, target[2])
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

// presetField fills a parameter field with values from the URL.
func presetField(f *paramField, vals []string) {
	switch f.Type {
	case modules.ParamMulti:
		for i := range f.Options {
			f.Options[i].Checked = slices.Contains(vals, f.Options[i].Value)
		}
	case modules.ParamList, modules.ParamText:
		f.Value = strings.Join(vals, "\n")
	case modules.ParamBool:
		f.Value = ""
		if len(vals) > 0 && vals[0] == "true" {
			f.Value = "true"
		}
	default:
		if len(vals) > 0 {
			f.Value = vals[0]
		}
		for i := range f.Options {
			f.Options[i].Checked = f.Options[i].Value == f.Value
		}
	}
}
