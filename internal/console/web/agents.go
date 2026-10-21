package web

import (
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/accesslog"
	"github.com/stefanozanarini/open-rmm/internal/adinv"
	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/ids"
	"github.com/stefanozanarini/open-rmm/internal/updates"
)

// agentRow is an agent in a list, with its status icons.
type agentRow struct {
	store.Agent
	Inv        store.InventorySummary
	Online     bool
	Checks     string // worst check status
	Site       string
	SiteManual bool   // assigned by hand, not by subnet
	OU         string // Active Directory container
	Alerts     int
	Reboot     bool
	Missing    int // missing security updates
	ThirdParty int
	Current    bool // shown in the bottom panel
	Checked    bool
}

type siteView struct {
	store.Site
	Count int
}

// panelTab is a tab of the bottom panel.
type panelTab struct {
	ID, Label, URL string
	Current        bool
}

type agentsData struct {
	Family, Query, Site, OU  string
	Counts                   map[string]int
	Sites                    []siteView
	NoSite                   int
	OUs                      []ouView // Active Directory containers holding agents
	Pending, Active, Revoked []agentRow
	Selected                 *agentData
	Tab                      string
	Tabs                     []panelTab
	// Links keep the current filters.
	SelectAllURL, ClearURL string
}

func (s *Server) online(a store.Agent) bool {
	return a.LastSeenAt != nil && s.now().Sub(*a.LastSeenAt) < 10*time.Minute
}

func (r agentRow) matches(q string) bool {
	for _, f := range []string{r.Host.Hostname, r.Inv.Model, r.Inv.Manufacturer, r.Inv.Serial, r.Inv.LoggedOnUser,
		r.Inv.SupremoID, r.Inv.AnyDeskID, r.Inv.TeamViewerID, r.Host.OSVersion, r.Site, r.OU} {
		if strings.Contains(strings.ToLower(f), q) {
			return true
		}
	}
	return false
}

// siteMatcher assigns agents to sites: by hand when an operator moved them,
// otherwise by their adapter or source address.
type siteMatcher struct {
	sites    []store.Site
	prefixes [][]netip.Prefix
	manual   map[string]string // agent → site
}

func newSiteMatcher(sites []store.Site, manual map[string]string) siteMatcher {
	m := siteMatcher{sites: sites, manual: manual}
	for _, st := range sites {
		p, _ := accesslog.ParseSubnets(st.Subnets)
		m.prefixes = append(m.prefixes, p)
	}
	return m
}

func (m siteMatcher) match(a store.Agent, inv store.InventorySummary) (id, name string, manual bool) {
	if want, ok := m.manual[a.ID]; ok {
		for _, st := range m.sites {
			if st.ID == want {
				return st.ID, st.Name, true
			}
		}
	}
	id, name = m.bySubnet(a, inv.IPv4)
	return id, name, false
}

func (m siteMatcher) bySubnet(a store.Agent, ipv4 []string) (id, name string) {
	addrs := append([]string(nil), ipv4...)
	if a.LastSeenIP != nil {
		addrs = append(addrs, a.LastSeenIP.String())
	}
	for i, st := range m.sites {
		for _, ip := range addrs {
			if accesslog.Allowed(ip, m.prefixes[i]) {
				return st.ID, st.Name
			}
		}
	}
	return "", ""
}

var tabs = []struct{ ID, Label string }{
	{"summary", "Riepilogo"}, {"checks", "Controlli"}, {"patches", "Patch"}, {"software", "Software"},
	{"inventory", "Inventario"}, {"logons", "Accessi"}, {"policies", "Raccolte"}, {"history", "Cronologia"},
	{"notes", "Note"}, {"commands", "Comandi"},
}

func (s *Server) handleAgents(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, s.T(r, "nessun tenant"), http.StatusForbidden)
		return
	}
	q := r.URL.Query()
	agents, err := s.store.ListAgents(r.Context(), t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	sums, err := s.store.InventorySummaries(r.Context(), t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	worst, err := s.store.WorstChecks(r.Context(), t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	sites, err := s.store.ListSites(r.Context(), t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	open, err := s.store.ListAlerts(r.Context(), t, "", true, 5000)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	alerts := map[string]int{}
	for _, a := range open {
		alerts[a.AgentID]++
	}
	statuses, err := s.store.ListUpdateStatus(r.Context(), t, "")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	snaps, err := s.adSnapshots(r.Context(), t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	places := adPlaces(snaps)
	d := agentsData{Family: q.Get("family"), Query: strings.TrimSpace(q.Get("q")), Site: q.Get("site"), OU: q.Get("ou"),
		Counts: map[string]int{}}
	if d.Family != "client" && d.Family != "server" {
		d.Family = ""
	}
	selected := q.Get("agent")
	checked := map[string]bool{}
	for _, id := range q["sel"] {
		checked[id] = true
	}
	all := q.Get("select") == "all"
	manual, err := s.store.AgentSites(r.Context(), t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	matcher := newSiteMatcher(sites, manual)
	siteCount := map[string]int{}
	var ouKeys []string
	needle := strings.ToLower(d.Query)
	for _, a := range agents {
		row := agentRow{Agent: a, Inv: sums[a.ID], Online: s.online(a), Checks: worst[a.ID], Alerts: alerts[a.ID],
			Current: a.ID == selected}
		var siteID string
		siteID, row.Site, row.SiteManual = matcher.match(a, row.Inv)
		ouKey := ""
		if pl, ok := places[adinv.HostKey(a.Host.Hostname)]; ok {
			row.OU, ouKey = pl.OU(), pl.Key()
		}
		for _, st := range statuses {
			if st.AgentID != a.ID {
				continue
			}
			switch st.Source {
			case updates.SourceWindows:
				row.Reboot, row.Missing = st.Reboot, st.Important
			case updates.SourceWinget:
				row.ThirdParty = st.ThirdParty
			}
		}
		// Counters follow the site and OU filters; the trees follow the family.
		inSite := d.Site == "" || d.Site == siteID || (d.Site == "none" && siteID == "")
		inUnit := d.OU == "" || inOU(ouKey, d.OU)
		if inSite && inUnit {
			d.Counts[""]++
			if a.Host.OSFamily == "client" || a.Host.OSFamily == "server" {
				d.Counts[a.Host.OSFamily]++
			}
		}
		if d.Family == "" || a.Host.OSFamily == d.Family {
			if siteID == "" {
				d.NoSite++
			} else {
				siteCount[siteID]++
			}
			if ouKey != "" {
				ouKeys = append(ouKeys, ouKey)
			}
		}
		if (d.Family != "" && a.Host.OSFamily != d.Family) || !inSite || !inUnit || (needle != "" && !row.matches(needle)) {
			continue
		}
		row.Checked = checked[a.ID] || (all && a.Status == store.AgentActive)
		switch a.Status {
		case store.AgentPending:
			d.Pending = append(d.Pending, row)
		case store.AgentActive:
			d.Active = append(d.Active, row)
		default:
			d.Revoked = append(d.Revoked, row)
		}
	}
	for _, st := range sites {
		d.Sites = append(d.Sites, siteView{Site: st, Count: siteCount[st.ID]})
	}
	d.OUs = ouTree(ouKeys)
	base := url.Values{}
	for _, k := range []string{"family", "q", "site", "ou"} {
		if v := q.Get(k); v != "" {
			base.Set(k, v)
		}
	}
	link := func(extra url.Values) string {
		v := url.Values{}
		for k, vs := range base {
			v[k] = vs
		}
		for k, vs := range extra {
			v[k] = vs
		}
		if len(v) == 0 {
			return "/agents"
		}
		return "/agents?" + v.Encode()
	}
	d.SelectAllURL, d.ClearURL = link(url.Values{"select": {"all"}}), link(nil)
	if selected != "" && ids.IsUUID(selected) {
		det, err := s.agentDetails(r, t, selected)
		switch {
		case errors.Is(err, store.ErrNotFound):
		case err != nil:
			s.fail(w, r, err)
			return
		default:
			det.Panel = true
			d.Selected = det
			d.Tab = q.Get("tab")
			valid := false
			for _, tb := range tabs {
				valid = valid || tb.ID == d.Tab
			}
			if !valid {
				d.Tab = "summary"
			}
			for _, tb := range tabs {
				d.Tabs = append(d.Tabs, panelTab{ID: tb.ID, Label: s.T(r, tb.Label), Current: tb.ID == d.Tab,
					URL: link(url.Values{"agent": {selected}, "tab": {tb.ID}})})
			}
			det.Return = link(url.Values{"agent": {selected}, "tab": {d.Tab}})
		}
	}
	title := map[string]string{"": "Agenti", "client": "Client", "server": "Server"}[d.Family]
	s.render(w, r, "agents", s.T(r, title), d)
}

// rowLink is the URL that opens an agent in the bottom panel.
func rowLink(d agentsData, agentID string) string {
	v := url.Values{"agent": {agentID}}
	if d.Family != "" {
		v.Set("family", d.Family)
	}
	if d.Query != "" {
		v.Set("q", d.Query)
	}
	if d.Site != "" {
		v.Set("site", d.Site)
	}
	if d.OU != "" {
		v.Set("ou", d.OU)
	}
	if d.Tab != "" {
		v.Set("tab", d.Tab)
	}
	return "/agents?" + v.Encode()
}

// rowTabLink opens an agent's panel on a tab, scrolled to hash (optional):
// how the status badges lead to the checks, the patches or the restart.
func rowTabLink(d agentsData, agentID, tab, hash string) string {
	d.Tab = tab
	l := rowLink(d, agentID)
	if hash != "" {
		l += "#" + hash
	}
	return l
}

// safeReturn keeps redirects inside the agent pages.
func safeReturn(ret, fallback string) string {
	if (strings.HasPrefix(ret, "/agents?") || strings.HasPrefix(ret, "/agents/")) && !strings.ContainsAny(ret, "\\\r\n") &&
		!strings.HasPrefix(ret, "//") {
		return ret
	}
	return fallback
}

func (s *Server) handleAddNote(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	id := r.PathValue("id")
	if !ok || !ids.IsUUID(id) {
		http.NotFound(w, r)
		return
	}
	op := sessionFrom(r.Context()).data.Operator
	back := safeReturn(r.PostFormValue("return"), "/agents/"+id)
	body := strings.TrimSpace(r.PostFormValue("body"))
	if body == "" || len(body) > 4000 {
		s.flash(w, r, s.T(r, "La nota deve avere da 1 a 4000 caratteri."), back)
		return
	}
	n := store.Note{TenantID: t, ID: ids.NewUUID(), AgentID: id, Body: body, Author: op.Name + " (" + op.Username + ")"}
	if err := s.store.AddNote(r.Context(), n); errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	} else if err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r.Context(), t, op, "agent.note_added", id, map[string]any{"note": n.ID})
	s.flash(w, r, s.T(r, "Nota aggiunta."), back)
}

// ---- sites ----

type sitesData struct {
	Sites []siteView
}

func (s *Server) handleSites(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, s.T(r, "nessun tenant"), http.StatusForbidden)
		return
	}
	sites, err := s.store.ListSites(r.Context(), t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var d sitesData
	for _, st := range sites {
		d.Sites = append(d.Sites, siteView{Site: st})
	}
	s.render(w, r, "sites", s.T(r, "Sedi"), d)
}

func (s *Server) handleSaveSite(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, s.T(r, "nessun tenant"), http.StatusForbidden)
		return
	}
	op := sessionFrom(r.Context()).data.Operator
	id := r.PostFormValue("id")
	if id == "" {
		id = ids.NewUUID()
	} else if !ids.IsUUID(id) {
		http.NotFound(w, r)
		return
	}
	if r.PostFormValue("delete") != "" {
		if err := s.store.DeleteSite(r.Context(), t, id); err != nil && !errors.Is(err, store.ErrNotFound) {
			s.fail(w, r, err)
			return
		}
		s.audit(r.Context(), t, op, "site.deleted", id, nil)
		s.flash(w, r, s.T(r, "Sede eliminata."), "/sites")
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	if !versionTxt.MatchString(name) {
		s.flash(w, r, s.T(r, "Nome della sede non valido."), "/sites")
		return
	}
	fields := strings.FieldsFunc(r.PostFormValue("subnets"), func(c rune) bool { return c == '\n' || c == '\r' || c == ',' || c == ' ' })
	prefixes, err := accesslog.ParseSubnets(fields)
	if err != nil || len(prefixes) > 100 {
		s.flash(w, r, s.T(r, "Subnet non valide (una per riga, es. 192.168.10.0/24, al massimo 100)."), "/sites")
		return
	}
	st := store.Site{TenantID: t, ID: id, Name: name}
	for _, p := range prefixes {
		st.Subnets = append(st.Subnets, p.String())
	}
	switch err := s.store.PutSite(r.Context(), st); {
	case errors.Is(err, store.ErrSiteExists):
		s.flash(w, r, s.T(r, "Esiste già una sede con questo nome."), "/sites")
		return
	case err != nil:
		s.fail(w, r, err)
		return
	}
	s.audit(r.Context(), t, op, "site.saved", id, map[string]any{"name": name, "subnets": st.Subnets})
	s.flash(w, r, s.Tf(r, "Sede %s salvata.", name), "/sites")
}

// ---- theme ----

func (s *Server) handleTheme(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	switch th := r.PostFormValue("theme"); th {
	case "light", "dark", "auto", "":
		sess.data.Theme = th
	}
	if err := s.save(r.Context(), w, sess); err != nil {
		s.fail(w, r, err)
		return
	}
	http.Redirect(w, r, safeReturn(r.PostFormValue("return"), "/agents"), http.StatusSeeOther)
}

// agentSite is the site of one agent, for its page.
type agentSite struct {
	Sites  []store.Site
	ID     string
	Name   string
	Manual bool
	// Auto is the site subnet matching would choose.
	Auto string
}

func (s *Server) agentSite(r *http.Request, t string, a store.Agent, ipv4 []string) (agentSite, error) {
	sites, err := s.store.ListSites(r.Context(), t)
	if err != nil {
		return agentSite{}, err
	}
	manual, err := s.store.AgentSites(r.Context(), t)
	if err != nil {
		return agentSite{}, err
	}
	m := newSiteMatcher(sites, manual)
	v := agentSite{Sites: sites}
	v.ID, v.Name, v.Manual = m.match(a, store.InventorySummary{IPv4: ipv4})
	_, v.Auto = m.bySubnet(a, ipv4)
	return v, nil
}

// moveAgents assigns agents to a site by hand ("" = back to automatic).
func (s *Server) moveAgents(r *http.Request, t string, agentIDs []string, site string) (int, error) {
	op := sessionFrom(r.Context()).data.Operator
	n := 0
	for _, id := range agentIDs {
		if !ids.IsUUID(id) {
			continue
		}
		if err := s.store.SetAgentSite(r.Context(), t, id, site, "operator:"+op.Username); err != nil {
			return n, err
		}
		s.audit(r.Context(), t, op, "agent.site_set", id, map[string]any{"site": site})
		n++
	}
	return n, nil
}

// handleMoveAgents moves the agents named in the "agent" values.
func (s *Server) handleMoveAgents(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, s.T(r, "nessun tenant"), http.StatusForbidden)
		return
	}
	_ = r.ParseForm()
	agents := r.PostForm["agent"]
	if id := r.PathValue("id"); id != "" {
		agents = []string{id}
	}
	site := r.PostFormValue("site")
	if site != "" && !ids.IsUUID(site) {
		http.NotFound(w, r)
		return
	}
	back := r.PostFormValue("return")
	if !strings.HasPrefix(back, "/agents") {
		back = "/agents"
	}
	if len(agents) == 0 || len(agents) > 1000 {
		s.flash(w, r, s.T(r, "Seleziona almeno un agente."), back)
		return
	}
	n, err := s.moveAgents(r, t, agents, site)
	if errors.Is(err, store.ErrNotFound) {
		s.flash(w, r, s.T(r, "Sede o agente non trovati."), back)
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if site == "" {
		s.flash(w, r, s.Tf(r, "%d agenti tornati all'assegnazione automatica per subnet.", n), back)
	} else {
		s.flash(w, r, s.Tf(r, "%d agenti spostati.", n), back)
	}
}
