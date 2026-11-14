package web

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/stefanozanarini/tempra-rmm/internal/console/store"
	"github.com/stefanozanarini/tempra-rmm/internal/console/vuln"
	"github.com/stefanozanarini/tempra-rmm/internal/inventory"
	"github.com/stefanozanarini/tempra-rmm/internal/updates"
)

// Reporting: questions over what the agents collected, answered from the
// stored inventories and logon events. Each report is a filter form with a
// table and a CSV export of the same rows.

const (
	maxReportLogons = 2000
	reportLogonDays = 30
	// maxFailedRank bounds the failed-logon ranking (computers, users).
	maxFailedRank = 15
)

type reportsData struct {
	Tab string // dashboard | software | computers | os | logons | cve
	// Software inventory.
	SW *swData
	// Vulnerabilities.
	Vulns *vulnData
	// Dashboard.
	Dash *dashData
	// Computers.
	Software, Version, OSFilter, User, Model, Site string
	// Expr: the advanced search (?q=), ExprError why it is not valid.
	Expr, ExprError string
	// ShowSoftware: the table lists the applications that matched.
	ShowSoftware bool
	Sites        []store.Site
	// Group: the dashboard can also be narrowed to one group (computer or
	// user); Groups lists the ones the operator can see.
	Group    string
	Groups   []store.Group
	Searched bool
	Rows     []reportRow
	// Columns: the inventory columns chosen (?col=), Choices all of them.
	Columns []invColumn
	Choices []columnChoice
	// Upgrades: the applications matching the software filter that winget
	// can upgrade on some of the computers found, with the action prepared
	// for them.
	Upgrades []reportUpgrade
	// Operating systems.
	OS []osGroup
	// Logons.
	LogonUser string
	Days      int
	Logons    []logonRow
	Truncated bool
	// FailedByAgent, FailedByUser: ranking of the most failed logons, the
	// same window as Logons.
	FailedByAgent, FailedByUser []failedRank
	// Query is the current filter, CSVURL the same as a CSV export.
	Query, CSVURL string
}

type reportRow struct {
	Agent    store.Agent
	Site     string
	OS       string
	Model    string
	User     string
	Software []inventory.Software // installed applications that matched
	Extra    []string             // values of the chosen columns
	Seen     time.Time            // inventory date
}

type reportUpgrade struct {
	ID, Name, Available string
	Count               int
	URL                 string // bulk form, action and computers filled in
}

type osGroup struct {
	Label string
	Count int
}

type logonRow struct {
	store.AgentLogon
	Hostname string
}

// failedRank is a ranking row: a computer (Label, Link to open it) or a
// user name, with its count of failed logons.
type failedRank struct {
	Label string
	Link  string // agents/{id}, "" for a user row
	Count int
}

// osLabel is how an operating system is named in reports: name, release
// and build, e.g. "Microsoft Windows 11 Pro 24H2 (26100.2605)".
func osLabel(a store.Agent, inv *inventory.Inventory) string {
	if inv == nil || inv.OS.Name == "" {
		return a.Host.OSVersion
	}
	l := inv.OS.Name
	if inv.OS.DisplayVersion != "" {
		l += " " + inv.OS.DisplayVersion
	}
	if inv.OS.Build != "" {
		l += " (" + inv.OS.Build + ")"
	}
	return l
}

func contains(s, sub string) bool {
	return sub == "" || strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}

func (s *Server) handleReports(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, s.T(r, "nessun tenant"), http.StatusForbidden)
		return
	}
	q := r.URL.Query()
	d := reportsData{Tab: q.Get("tab"), Software: strings.TrimSpace(q.Get("software")), Version: strings.TrimSpace(q.Get("version")),
		OSFilter: strings.TrimSpace(q.Get("os")), User: strings.TrimSpace(q.Get("user")), Model: strings.TrimSpace(q.Get("model")),
		Site: q.Get("site"), Group: q.Get("group"), Expr: strings.TrimSpace(q.Get("q")), LogonUser: strings.TrimSpace(q.Get("logon_user")), Days: reportLogonDays}
	if n, err := strconv.Atoi(q.Get("days")); err == nil && n > 0 && n <= 365 {
		d.Days = n
	}
	switch d.Tab {
	case "software", "computers", "os", "logons", "cve":
	default:
		d.Tab = "dashboard"
	}
	d.Columns, d.Choices = selectedColumns(q["col"])
	csvOut := q.Get("format") == "csv"
	qq := q
	qq.Del("format")
	d.Query = qq.Encode()
	d.CSVURL = "/reports?" + d.Query + "&format=csv"
	ctx := r.Context()

	if d.Tab == "dashboard" {
		sites, err := s.store.ListSites(ctx, t)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		d.Sites = sites
		groups, err := s.visibleGroups(r, t)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		d.Groups = groups
		dash, err := s.dashboard(r, s.lang(r), t, d.Site, d.Group)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		d.Dash = dash
		s.render(w, r, "reports", s.T(r, "Reporting"), d)
		return
	}

	if d.Tab == "software" {
		sw, ok := s.softwareInventory(w, r, t)
		if !ok {
			return
		}
		d.SW = sw
		s.render(w, r, "reports", s.T(r, "Reporting"), d)
		return
	}

	if d.Tab == "cve" {
		v, err := s.vulnReport(r, t)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		d.Vulns = v
		s.render(w, r, "reports", s.T(r, "Reporting"), d)
		return
	}

	if d.Tab == "logons" {
		agents, err := s.store.ListAgents(ctx, t)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		names := map[string]string{}
		for _, a := range agents {
			names[a.ID] = a.Host.Hostname
		}
		evs, err := s.store.SearchLogons(ctx, t, d.LogonUser, s.now().AddDate(0, 0, -d.Days), maxReportLogons+1)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if len(evs) > maxReportLogons {
			evs, d.Truncated = evs[:maxReportLogons], true
		}
		for _, e := range evs {
			d.Logons = append(d.Logons, logonRow{AgentLogon: e, Hostname: names[e.AgentID]})
		}
		byAgent, byUser, err := s.store.TopFailedLogons(ctx, t, s.now().AddDate(0, 0, -d.Days), maxFailedRank)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		for _, fr := range byAgent {
			label, link := fr.Key, ""
			if name, ok := names[fr.Key]; ok {
				label, link = name, "/agents/"+fr.Key
			}
			d.FailedByAgent = append(d.FailedByAgent, failedRank{Label: label, Link: link, Count: fr.Count})
		}
		for _, fr := range byUser {
			d.FailedByUser = append(d.FailedByUser, failedRank{Label: fr.Key, Count: fr.Count})
		}
		if csvOut {
			s.writeCSV(w, "logons.csv", []string{"computer", "time", "user", "domain", "kind", "logon_type", "source_ip", "source_host", "status"},
				func(add func(...string)) {
					for _, l := range d.Logons {
						add(l.Hostname, l.At.UTC().Format(time.RFC3339), l.User, l.Domain, l.Kind, strconv.Itoa(l.LogonType), l.SourceIP, l.SourceHost, l.Status)
					}
				})
			return
		}
		s.render(w, r, "reports", s.T(r, "Reporting"), d)
		return
	}

	agents, err := s.store.ListAgents(ctx, t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	invs, err := s.store.ListInventories(ctx, t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	byAgent := map[string]store.Inventory{}
	for _, i := range invs {
		byAgent[i.AgentID] = i
	}
	sites, err := s.store.ListSites(ctx, t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	manual, err := s.store.AgentSites(ctx, t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d.Sites = sites
	matcher := newSiteMatcher(sites, manual)
	osCount := map[string]int{}
	d.Searched = d.Software != "" || d.Version != "" || d.OSFilter != "" || d.User != "" || d.Model != "" || d.Site != "" || d.Expr != "" ||
		q.Has("all") || q.Has("search")
	expr, err := parseQuery(d.Expr, s.now())
	if err != nil && d.Tab == "computers" {
		d.ExprError = queryErrorText(s.lang(r), err)
		csvOut = false
	}
	swTerms := softwareTerms(expr)
	d.ShowSoftware = d.Software != "" || d.Version != "" || len(swTerms) > 0
	lastUsers, userTTL := s.lastUsers(r.Context(), t)
	for _, a := range agents {
		if a.Status == store.AgentRevoked {
			continue
		}
		stored, has := byAgent[a.ID]
		var inv *inventory.Inventory
		if has {
			if parsed, err := inventory.Parse(stored.Data); err == nil {
				inv = parsed
			}
		}
		siteID, siteName, _ := matcher.match(a, stored.Summary)
		row := reportRow{Agent: a, Site: siteName, OS: osLabel(a, inv), Seen: stored.ReceivedAt,
			Model: strings.TrimSpace(stored.Summary.Manufacturer + " " + stored.Summary.Model)}
		lu, hasLU := lastUsers[a.ID]
		row.User = s.userFor(a, stored.Summary, lu, hasLU, userTTL).Name
		osCount[row.OS]++
		if d.Tab != "computers" || !d.Searched || d.ExprError != "" {
			continue
		}
		if !contains(row.OS, d.OSFilter) || !contains(row.User, d.User) || !contains(row.Model, d.Model) {
			continue
		}
		if d.Site != "" && (d.Site != siteID && !(d.Site == "none" && siteID == "")) {
			continue
		}
		if d.Software != "" || d.Version != "" {
			if inv == nil {
				continue
			}
			for _, sw := range inv.VisibleSoftware() {
				if contains(sw.Name, d.Software) && contains(sw.Version, d.Version) {
					row.Software = append(row.Software, sw)
				}
			}
			if len(row.Software) == 0 {
				continue
			}
		}
		if expr != nil {
			qc := &queryCtx{lang: s.lang(r), now: s.now(), a: a, inv: inv, row: &row}
			if inv == nil {
				qc.inv = &inventory.Inventory{}
			}
			if !expr.eval(qc) {
				continue
			}
			seen := map[string]bool{}
			for _, sw := range row.Software {
				seen[sw.Name+"\x00"+sw.Version] = true
			}
			for _, t := range swTerms {
				for _, sw := range t.apps(qc) {
					if k := sw.Name + "\x00" + sw.Version; !seen[k] {
						seen[k] = true
						row.Software = append(row.Software, sw)
					}
				}
			}
		}
		row.Extra = columnValues(s.lang(r), d.Columns, a, inv)
		d.Rows = append(d.Rows, row)
	}
	sort.Slice(d.Rows, func(i, j int) bool {
		return strings.ToLower(d.Rows[i].Agent.Host.Hostname) < strings.ToLower(d.Rows[j].Agent.Host.Hostname)
	})
	if d.Software != "" && len(d.Rows) > 0 && !csvOut {
		if d.Upgrades, err = s.reportUpgrades(r, t, d.Software, d.Rows); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	for l, n := range osCount {
		d.OS = append(d.OS, osGroup{Label: l, Count: n})
	}
	sort.Slice(d.OS, func(i, j int) bool {
		if d.OS[i].Count != d.OS[j].Count {
			return d.OS[i].Count > d.OS[j].Count
		}
		return d.OS[i].Label < d.OS[j].Label
	})
	if csvOut {
		switch d.Tab {
		case "os":
			s.writeCSV(w, "operating-systems.csv", []string{"operating_system", "computers"}, func(add func(...string)) {
				for _, g := range d.OS {
					add(g.Label, strconv.Itoa(g.Count))
				}
			})
		default:
			header := []string{"computer", "site", "operating_system", "model", "user", "software", "version", "inventory"}
			for _, c := range d.Columns {
				header = append(header, c.Key)
			}
			s.writeCSV(w, "inventory.csv", header, func(add func(...string)) {
				for _, row := range d.Rows {
					seen := ""
					if !row.Seen.IsZero() {
						seen = row.Seen.UTC().Format(time.RFC3339)
					}
					line := func(name, version string) {
						add(append([]string{row.Agent.Host.Hostname, row.Site, row.OS, row.Model, row.User, name, version, seen}, row.Extra...)...)
					}
					if len(row.Software) == 0 {
						line("", "")
					}
					for _, sw := range row.Software {
						line(sw.Name, sw.Version)
					}
				}
			})
		}
		return
	}
	s.render(w, r, "reports", s.T(r, "Reporting"), d)
}

// writeCSV sends rows as a CSV download. Cells starting with a formula
// character are prefixed with a quote, so a spreadsheet does not run them.
func (s *Server) writeCSV(w http.ResponseWriter, name string, header []string, rows func(add func(...string))) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
	cw := csv.NewWriter(w)
	_ = cw.Write(header)
	rows(func(cells ...string) {
		for i, c := range cells {
			if c != "" && strings.ContainsRune("=+-@\t\r", rune(c[0])) {
				cells[i] = "'" + c
			}
		}
		_ = cw.Write(cells)
	})
	cw.Flush()
}

// reportUpgrades lists, per winget id, the computers found that winget can
// upgrade for an application whose name contains software.
func (s *Server) reportUpgrades(r *http.Request, t, software string, rows []reportRow) ([]reportUpgrade, error) {
	_, perAgent, err := s.outdatedApps(r, t)
	if err != nil {
		return nil, err
	}
	var out []reportUpgrade
	for id, agents := range perAgent {
		u := reportUpgrade{ID: id}
		q := url.Values{"action": {updates.WingetModule + ".upgrade"}, "p.ids": {id}}
		for _, row := range rows {
			app, ok := agents[row.Agent.ID]
			if !ok || row.Agent.Status != store.AgentActive || !contains(app.Name, software) {
				continue
			}
			u.Count++
			q.Add("agent", row.Agent.ID)
			if u.Name == "" || vuln.CompareVersions(app.Available, u.Available) > 0 {
				u.Name, u.Available = app.Name, app.Available
			}
		}
		if u.Count > 0 {
			u.URL = "/agents/bulk?" + q.Encode()
			out = append(out, u)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}
