package web

import (
	"encoding/json"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/open-rmm/internal/console/jobreq"
	"github.com/stefanozanarini/open-rmm/internal/ids"
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
	Firmware   *store.UpdateStatus
	BIOS       bool // BIOS update pending
	Score      int
	Stale      bool
	RebootDays int
	// WingetMissing: winget is not installed on the endpoint.
	WingetMissing bool
}

// appRow is a third-party application outdated on several agents.
type appRow struct {
	ID, Name, Available string
	Agents              int
}

type patchesData struct {
	Family string
	// Show filters the table: missing, behind, reboot, apps, firmware,
	// stale (empty: every endpoint).
	Show           string
	Rows           []patchRow
	Apps           []appRow
	Total          int
	MissingSec     int
	Behind         int // more than one Patch Tuesday behind
	RebootPending  int
	ThirdParty     int
	Firmware       int // agents with firmware or driver updates
	BIOS           int // agents with a BIOS update
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
	d := patchesData{Family: r.URL.Query().Get("family"), Show: r.URL.Query().Get("show")}
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
				row.WingetMissing = rep.Missing()
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
		if st, ok := byAgent[a.ID][updates.SourceFirmware]; ok {
			row.Firmware = &st
			var rep updates.FirmwareReport
			if json.Unmarshal(st.Data, &rep) == nil {
				_, _, row.BIOS = rep.Counts()
			}
			row.Score += st.Important*5 + st.Other
			if row.BIOS {
				row.Score += 5
				d.BIOS++
			}
			if st.Important+st.Other > 0 {
				d.Firmware++
			}
		}
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
		// The cards filter the table.
		keep := true
		switch d.Show {
		case "missing":
			keep = sum.Important > 0
		case "behind":
			keep = sum.Behind > 1
		case "reboot":
			keep = sum.Reboot
		case "apps":
			keep = third > 0
		case "firmware":
			keep = row.Firmware != nil && row.Firmware.Important+row.Firmware.Other > 0
		case "stale":
			keep = row.Stale
		case "compliant":
			keep = !row.Stale && sum.Important == 0
		}
		if keep {
			d.Rows = append(d.Rows, row)
		}
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
	Windows  *updates.WindowsReport
	WinScan  time.Time
	Winget   *updates.WingetReport
	WingetAt time.Time
	Firmware *updates.FirmwareReport
	// FirmwareVersion is the newest published firmware module, for the
	// install form.
	FirmwareVersion string
	Summary         updates.Summary
	HasReport       bool
	// Patch table: missing and installed Windows updates, filtered by
	// Query; WinupdateVersion is the module version used to install.
	Rows             []updateRow
	Missing          int
	HiddenHistory    int // older installations left out (no search)
	Query            string
	WinupdateVersion string
	// WingetVersion is the module version used to upgrade applications.
	WingetVersion   string
	Classifications []string
}

// updateRow is a Windows update in the patch table of an agent.
type updateRow struct {
	State    string // missing | succeeded | failed | other result
	Severity string
	Title    string
	KBs      []string
	Link     string // Microsoft support page of the first KB
	Date     *time.Time
	Selected bool
	// Failure is the last failed installation of a missing update.
	Failure *updateFailure
}

// updateFailure is a failed attempt to install an update.
type updateFailure struct {
	Code string // HRESULT, e.g. 0x80240022; empty when unknown
	Text string // what it means, Italian (translated in the template)
	At   *time.Time
	Job  string // the install job, when the failure comes from one
}

// kbLink is the Microsoft support page of a KB article.
func kbLink(kbs []string) string {
	if len(kbs) == 0 {
		return ""
	}
	return "https://support.microsoft.com/help/" + strings.TrimPrefix(kbs[0], "KB")
}

// maxHistoryRows is how many past installations the patch table lists when
// not searching: the most recent ones.
const maxHistoryRows = 10

func updateRows(rep *updates.WindowsReport, q string) (rows []updateRow, missing, hidden int) {
	var out []updateRow
	match := func(title string, kbs []string) bool {
		return q == "" || contains(title, q) || contains(strings.Join(kbs, " "), q)
	}
	for _, u := range rep.Updates {
		missing++
		if !match(u.Title, u.KBs) {
			continue
		}
		sev := u.Severity
		if sev == "" {
			sev = u.Classification
		}
		out = append(out, updateRow{State: "missing", Severity: sev, Title: u.Title, KBs: u.KBs, Link: kbLink(u.KBs),
			Date: u.Released, Selected: u.Important()})
	}
	var past []updateRow
	for _, h := range rep.History {
		if !match(h.Title, h.KBs) {
			continue
		}
		row := updateRow{State: h.Result, Title: h.Title, KBs: h.KBs, Link: kbLink(h.KBs), Date: h.Date}
		if h.HResult != "" {
			row.Failure = &updateFailure{Code: h.HResult, Text: hresultText(h.HResult, h.Result)}
		}
		past = append(past, row)
	}
	sort.SliceStable(past, func(i, j int) bool {
		a, b := past[i].Date, past[j].Date
		return a != nil && (b == nil || a.After(*b))
	})
	if q == "" && len(past) > maxHistoryRows {
		past, hidden = past[:maxHistoryRows], len(past)-maxHistoryRows
	}
	return append(out, past...), missing, hidden
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
		case updates.SourceFirmware:
			var rep updates.FirmwareReport
			if json.Unmarshal(st.Data, &rep) == nil {
				out.Firmware, out.HasReport = &rep, true
			}
		}
	}
	latest, err := s.latestModules(r)
	if err != nil {
		return out, err
	}
	if out.Firmware != nil {
		out.FirmwareVersion = latest[updates.FirmwareModule]
	}
	out.WinupdateVersion = latest["winupdate"]
	out.WingetVersion = latest["winget"]
	out.Classifications = []string{"security", "critical", "rollup", "update", "definition", "driver", "feature_pack", "service_pack", "tools", "upgrade"}
	if out.Windows != nil {
		out.Query = strings.TrimSpace(r.URL.Query().Get("pq"))
		out.Rows, out.Missing, out.HiddenHistory = updateRows(out.Windows, out.Query)
		failures := s.updateFailures(r, tenant, agent, out.Windows)
		for i := range out.Rows {
			if out.Rows[i].State != "missing" {
				continue
			}
			for _, kb := range out.Rows[i].KBs {
				if f, ok := failures[kb]; ok {
					out.Rows[i].Failure = f
					break
				}
			}
		}
	}
	return out, nil
}

// updateFailures returns the last failed installation of each KB, from the
// Windows Update history and from the agent's recent install jobs.
func (s *Server) updateFailures(r *http.Request, tenant, agent string, rep *updates.WindowsReport) map[string]*updateFailure {
	out := map[string]*updateFailure{}
	add := func(kbs []string, f *updateFailure) {
		for _, kb := range kbs {
			kb = strings.ToUpper(kb)
			if cur, ok := out[kb]; !ok || (f.At != nil && (cur.At == nil || f.At.After(*cur.At))) {
				out[kb] = f
			}
		}
	}
	for _, h := range rep.History {
		if h.Result == "failed" || h.Result == "aborted" || h.Result == "succeeded_with_errors" {
			add(h.KBs, &updateFailure{Code: h.HResult, Text: hresultText(h.HResult, h.Result), At: h.Date})
		}
	}
	jobs, err := s.store.ListJobs(r.Context(), tenant, agent, 100)
	if err != nil {
		return out
	}
	for _, j := range jobs {
		if j.Module != "winupdate" || j.Action != "install" || j.FinishedAt == nil || len(j.Result) == 0 {
			continue
		}
		var res struct {
			Installed []struct {
				KBs     []string `json:"kbs"`
				Result  string   `json:"result"`
				HResult string   `json:"hresult"`
			} `json:"installed"`
		}
		if json.Unmarshal(j.Result, &res) != nil {
			continue
		}
		for _, x := range res.Installed {
			if x.Result == "succeeded" || x.Result == "succeeded_with_errors" {
				continue
			}
			code := strings.ToUpper(x.HResult)
			if code = strings.Replace(code, "0X", "0x", 1); !updates.HResultRe.MatchString(code) || code == "0x00000000" {
				code = ""
			}
			add(x.KBs, &updateFailure{Code: code, Text: hresultText(code, x.Result), At: j.FinishedAt, Job: j.ID})
		}
	}
	return out
}

// handleFirmwareInstall installs vendor updates on one agent, with the
// operator's MFA approval. BIOS updates are included only on request.
func (s *Server) handleFirmwareInstall(w http.ResponseWriter, r *http.Request) {
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
	if err := r.ParseForm(); err != nil {
		http.Error(w, s.T(r, "richiesta non valida"), http.StatusBadRequest)
		return
	}
	var types []string
	for _, v := range r.PostForm["types"] {
		if v == "firmware" || v == "driver" || v == "application" {
			types = append(types, v)
		}
	}
	bios := r.PostFormValue("include_bios") != ""
	if len(types) == 0 && !bios {
		s.flash(w, r, s.T(r, "Seleziona almeno un tipo di aggiornamento."), back)
		return
	}
	severity := r.PostFormValue("severity")
	if severity != "critical" && severity != "recommended" {
		severity = "all"
	}
	latest, err := s.latestModules(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	mod, err := s.store.GetModule(r.Context(), updates.FirmwareModule, latest[updates.FirmwareModule])
	if err != nil {
		s.flash(w, r, s.T(r, "Modulo non trovato."), back)
		return
	}
	params, err := json.Marshal(map[string]any{"types": types, "include_bios": bios, "severity": severity})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	req := &openrmmv1.JobRequest{TenantId: t, AgentId: id, Module: mod.ID, ModuleVersion: mod.Version, ModuleSha256: mod.ManifestSHA256,
		Action: "install", ParamsJson: params, TtlSeconds: 4 * 3600, RequestNonce: jobreq.NewRequestNonce()}
	if err := jobreq.Validate(req); err != nil {
		s.flash(w, r, s.Tf(r, "Richiesta non valida: %v", err), back)
		return
	}
	s.startStepUp(w, r, sessionFrom(r.Context()), req, back)
}
