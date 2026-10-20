package web

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/inventory"
)

// Reporting: questions over what the agents collected, answered from the
// stored inventories and logon events. Each report is a filter form with a
// table and a CSV export of the same rows.

const (
	maxReportLogons = 2000
	reportLogonDays = 30
)

type reportsData struct {
	Tab string // computers | os | logons
	// Computers.
	Software, Version, OSFilter, User, Model, Site string
	Sites                                          []store.Site
	Searched                                       bool
	Rows                                           []reportRow
	// Operating systems.
	OS []osGroup
	// Logons.
	LogonUser string
	Days      int
	Logons    []logonRow
	Truncated bool
	// Query is the current filter, for the CSV link.
	Query string
}

type reportRow struct {
	Agent    store.Agent
	Site     string
	OS       string
	Model    string
	User     string
	Software []inventory.Software // installed applications that matched
	Seen     time.Time            // inventory date
}

type osGroup struct {
	Label string
	Count int
}

type logonRow struct {
	store.AgentLogon
	Hostname string
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
		Site: q.Get("site"), LogonUser: strings.TrimSpace(q.Get("logon_user")), Days: reportLogonDays}
	if n, err := strconv.Atoi(q.Get("days")); err == nil && n > 0 && n <= 365 {
		d.Days = n
	}
	switch d.Tab {
	case "os", "logons":
	default:
		d.Tab = "computers"
	}
	csvOut := q.Get("format") == "csv"
	qq := q
	qq.Del("format")
	d.Query = qq.Encode()
	ctx := r.Context()

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
	d.Searched = d.Software != "" || d.Version != "" || d.OSFilter != "" || d.User != "" || d.Model != "" || d.Site != "" || q.Has("all")
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
			Model: strings.TrimSpace(stored.Summary.Manufacturer + " " + stored.Summary.Model), User: stored.Summary.LoggedOnUser}
		osCount[row.OS]++
		if d.Tab != "computers" || !d.Searched {
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
		d.Rows = append(d.Rows, row)
	}
	sort.Slice(d.Rows, func(i, j int) bool {
		return strings.ToLower(d.Rows[i].Agent.Host.Hostname) < strings.ToLower(d.Rows[j].Agent.Host.Hostname)
	})
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
			s.writeCSV(w, "computers.csv", []string{"computer", "site", "operating_system", "model", "user", "software", "version", "inventory"},
				func(add func(...string)) {
					for _, row := range d.Rows {
						seen := ""
						if !row.Seen.IsZero() {
							seen = row.Seen.UTC().Format(time.RFC3339)
						}
						if len(row.Software) == 0 {
							add(row.Agent.Host.Hostname, row.Site, row.OS, row.Model, row.User, "", "", seen)
						}
						for _, sw := range row.Software {
							add(row.Agent.Host.Hostname, row.Site, row.OS, row.Model, row.User, sw.Name, sw.Version, seen)
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
