package web

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/updates"
)

// staleScan: an agent whose last scan is older is counted as not scanned.
const staleScan = 7 * 24 * time.Hour

// patchRow is one agent in the update dashboard.
type patchRow struct {
	Agent      store.Agent
	Online     bool
	Windows    *store.UpdateStatus
	Winget     *store.UpdateStatus
	Score      int
	Stale      bool
	RebootDays int
}

// appRow is a third-party application outdated on several agents.
type appRow struct {
	ID, Name, Available string
	Agents              int
}

type patchesData struct {
	Family         string
	Rows           []patchRow
	Apps           []appRow
	Total          int
	MissingSec     int
	Behind         int // more than one Patch Tuesday behind
	RebootPending  int
	ThirdParty     int
	NotScanned     int
	Managed        int // WSUS or Intune: observed only
	Compliant      int
	ComplianceRate int
}

func (s *Server) handlePatches(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, s.T(r, "nessun tenant"), http.StatusForbidden)
		return
	}
	agents, err := s.store.ListAgents(r.Context(), t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	statuses, err := s.store.ListUpdateStatus(r.Context(), t, "")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	byAgent := map[string]map[string]store.UpdateStatus{}
	for _, st := range statuses {
		if byAgent[st.AgentID] == nil {
			byAgent[st.AgentID] = map[string]store.UpdateStatus{}
		}
		byAgent[st.AgentID][st.Source] = st
	}
	d := patchesData{Family: r.URL.Query().Get("family")}
	if d.Family != "client" && d.Family != "server" {
		d.Family = ""
	}
	now := s.now()
	apps := map[string]*appRow{}
	for _, a := range agents {
		if a.Status != store.AgentActive || (d.Family != "" && a.Host.OSFamily != d.Family) {
			continue
		}
		row := patchRow{Agent: a, Online: s.online(a)}
		var sum updates.Summary
		third := 0
		if st, ok := byAgent[a.ID][updates.SourceWindows]; ok {
			row.Windows = &st
			sum = updates.Summary{Important: st.Important, Other: st.Other, OldestDays: st.OldestDays, Behind: st.Behind,
				Reboot: st.Reboot, RebootSince: st.RebootSince}
			if st.RebootSince != nil {
				row.RebootDays = int(now.Sub(*st.RebootSince).Hours() / 24)
			}
		}
		if st, ok := byAgent[a.ID][updates.SourceWinget]; ok {
			row.Winget = &st
			third = st.ThirdParty
			var rep updates.WingetReport
			if json.Unmarshal(st.Data, &rep) == nil {
				for _, app := range rep.Upgrades {
					x := apps[app.ID]
					if x == nil {
						x = &appRow{ID: app.ID, Name: app.Name}
						apps[app.ID] = x
					}
					x.Agents++
					if app.Available > x.Available {
						x.Available = app.Available
					}
				}
			}
		}
		row.Score = updates.Score(sum, third, now)
		row.Stale = row.Windows == nil || now.Sub(row.Windows.ScannedAt) > staleScan
		d.Total++
		switch {
		case row.Stale:
			d.NotScanned++
		case sum.Important == 0:
			d.Compliant++
		}
		if sum.Important > 0 {
			d.MissingSec++
		}
		if sum.Behind > 1 {
			d.Behind++
		}
		if sum.Reboot {
			d.RebootPending++
		}
		if third > 0 {
			d.ThirdParty++
		}
		if row.Windows != nil && row.Windows.ManagedBy != "none" {
			d.Managed++
		}
		d.Rows = append(d.Rows, row)
	}
	if d.Total > 0 {
		d.ComplianceRate = 100 * d.Compliant / d.Total
	}
	sort.SliceStable(d.Rows, func(i, j int) bool {
		if d.Rows[i].Stale != d.Rows[j].Stale {
			return !d.Rows[i].Stale
		}
		if d.Rows[i].Score != d.Rows[j].Score {
			return d.Rows[i].Score > d.Rows[j].Score
		}
		return strings.ToLower(d.Rows[i].Agent.Host.Hostname) < strings.ToLower(d.Rows[j].Agent.Host.Hostname)
	})
	for _, a := range apps {
		d.Apps = append(d.Apps, *a)
	}
	sort.Slice(d.Apps, func(i, j int) bool {
		if d.Apps[i].Agents != d.Apps[j].Agents {
			return d.Apps[i].Agents > d.Apps[j].Agents
		}
		return d.Apps[i].Name < d.Apps[j].Name
	})
	if len(d.Apps) > 30 {
		d.Apps = d.Apps[:30]
	}
	title := map[string]string{"": "Patch", "client": "Patch · client", "server": "Patch · server"}[d.Family]
	s.render(w, r, "patches", s.T(r, title), d)
}

// agentUpdates is the update section of the agent page.
type agentUpdates struct {
	Windows   *updates.WindowsReport
	WinScan   time.Time
	Winget    *updates.WingetReport
	WingetAt  time.Time
	Summary   updates.Summary
	HasReport bool
}

func (s *Server) agentUpdates(r *http.Request, tenant, agent string) (agentUpdates, error) {
	var out agentUpdates
	list, err := s.store.ListUpdateStatus(r.Context(), tenant, agent)
	if err != nil {
		return out, err
	}
	for _, st := range list {
		switch st.Source {
		case updates.SourceWindows:
			var rep updates.WindowsReport
			if json.Unmarshal(st.Data, &rep) == nil {
				out.Windows, out.WinScan, out.HasReport = &rep, st.ScannedAt, true
				out.Summary = rep.Summarize(s.now())
			}
		case updates.SourceWinget:
			var rep updates.WingetReport
			if json.Unmarshal(st.Data, &rep) == nil {
				out.Winget, out.WingetAt, out.HasReport = &rep, st.ScannedAt, true
			}
		}
	}
	return out, nil
}
