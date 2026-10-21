package web

import (
	"encoding/json"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/console/wingetcat"
	"github.com/stefanozanarini/open-rmm/internal/updates"
)

// Upgrading one application on every endpoint that needs it, or on those
// of one site: the endpoints come from the last winget scans, the jobs are
// created by the bulk action form (one MFA approval for all).

var wingetIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_-]{0,127}$`)

type appTarget struct {
	Agent     store.Agent
	Site      string
	Version   string
	Available string
	Online    bool
}

type appUpgradeData struct {
	ID, Name, Available string
	Site                string // filter: "" every site, "none" no site, or a site id
	Sites               []store.Site
	Targets             []appTarget
	Version             string // winget module version
}

// outdatedApps returns, per winget id, the active agents that can upgrade
// it, with the scan's application entry.
func (s *Server) outdatedApps(r *http.Request, t string) (map[string][]updates.App, map[string]map[string]updates.App, error) {
	statuses, err := s.store.ListUpdateStatus(r.Context(), t, "")
	if err != nil {
		return nil, nil, err
	}
	byApp := map[string][]updates.App{}
	perAgent := map[string]map[string]updates.App{} // app id -> agent -> entry
	for _, st := range statuses {
		if st.Source != updates.SourceWinget {
			continue
		}
		var rep updates.WingetReport
		if json.Unmarshal(st.Data, &rep) != nil || rep.Missing() {
			continue
		}
		for _, app := range rep.Upgrades {
			byApp[app.ID] = append(byApp[app.ID], app)
			if perAgent[app.ID] == nil {
				perAgent[app.ID] = map[string]updates.App{}
			}
			perAgent[app.ID][st.AgentID] = app
		}
	}
	return byApp, perAgent, nil
}

func (s *Server) handleAppUpgrade(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, s.T(r, "nessun tenant"), http.StatusForbidden)
		return
	}
	q := r.URL.Query()
	d := appUpgradeData{ID: q.Get("id"), Site: q.Get("site")}
	if !wingetIDRe.MatchString(d.ID) {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()
	_, perAgent, err := s.outdatedApps(r, t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if mod, found, err := s.latestModule(ctx, "winget"); err != nil {
		s.fail(w, r, err)
		return
	} else if found {
		d.Version = mod.Version
	}
	if d.Sites, err = s.store.ListSites(ctx, t); err != nil {
		s.fail(w, r, err)
		return
	}
	manual, err := s.store.AgentSites(ctx, t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	invs, err := s.store.ListInventories(ctx, t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	summaries := map[string]store.InventorySummary{}
	for _, i := range invs {
		summaries[i.AgentID] = i.Summary
	}
	matcher := newSiteMatcher(d.Sites, manual)
	for agentID, app := range perAgent[d.ID] {
		a, err := s.store.GetAgent(ctx, t, agentID)
		if err != nil || a.Status != store.AgentActive {
			continue
		}
		siteID, siteName, _ := matcher.match(a, summaries[a.ID])
		if d.Site != "" && d.Site != siteID && !(d.Site == "none" && siteID == "") {
			continue
		}
		if d.Name == "" {
			d.Name = app.Name
		}
		if wingetcat.CompareVersions(app.Available, d.Available) > 0 {
			d.Available = app.Available
		}
		d.Targets = append(d.Targets, appTarget{Agent: a, Site: siteName, Version: app.Version, Available: app.Available, Online: s.online(a)})
	}
	sort.Slice(d.Targets, func(i, j int) bool {
		return strings.ToLower(d.Targets[i].Agent.Host.Hostname) < strings.ToLower(d.Targets[j].Agent.Host.Hostname)
	})
	if d.Name == "" {
		d.Name = d.ID
	}
	s.render(w, r, "appupgrade", s.Tf(r, "Aggiorna %s", d.Name), d)
}
