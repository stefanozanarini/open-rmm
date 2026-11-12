package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/stefanozanarini/tempra-rmm/internal/console/store"
	"github.com/stefanozanarini/tempra-rmm/internal/console/vuln"
	"github.com/stefanozanarini/tempra-rmm/internal/inventory"
	"github.com/stefanozanarini/tempra-rmm/internal/updates"
)

// CVEs affecting the endpoints (Reporting → Vulnerabilities). The sources
// are downloaded in the background (RefreshVulns, every few hours); the
// loaded index is kept in memory for a few minutes.

// vulnCacheTTL is how long the loaded extracts are reused.
const vulnCacheTTL = 10 * time.Minute

type vulnCache struct {
	mu      sync.Mutex
	ix      *vuln.Index
	matched map[string]*vulnMatch // by tenant
}

// RefreshVulns downloads the vulnerability sources that are missing or
// changed. Called periodically by openrmm-server.
func (s *Server) RefreshVulns(ctx context.Context) error {
	f := vuln.NewFetcher(s.store, s.log)
	err := f.Refresh(ctx)
	// Title and CVSS of the CVEs named by Linux package managers.
	if ids, e := s.linuxCVEs(ctx); e == nil && len(ids) > 0 {
		if e := f.RefreshDetails(ctx, ids); e != nil {
			s.log.Warn("vulnerability details", "err", e)
		}
	}
	s.vulns.mu.Lock()
	s.vulns.ix = nil
	for _, m := range s.vulns.matched {
		m.at = time.Time{} // computed again at the next view
	}
	s.vulns.mu.Unlock()
	return err
}

func (s *Server) vulnIndex(ctx context.Context) (*vuln.Index, error) {
	s.vulns.mu.Lock()
	defer s.vulns.mu.Unlock()
	if s.vulns.ix != nil && time.Since(s.vulns.ix.LoadedAt) < vulnCacheTTL {
		return s.vulns.ix, nil
	}
	ix, err := vuln.Load(ctx, s.store)
	if err != nil {
		return nil, err // ErrNoData included: not cached, the download may end any moment
	}
	s.vulns.ix = ix
	return ix, nil
}

// linuxCVEs lists the CVEs of the pending Linux updates of every tenant.
func (s *Server) linuxCVEs(ctx context.Context) ([]string, error) {
	tenants, err := s.store.ListTenants(ctx)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for _, t := range tenants {
		list, err := s.store.ListUpdateStatus(ctx, t.ID, "")
		if err != nil {
			return nil, err
		}
		for _, st := range list {
			rep := osUpdateReport(st)
			if rep == nil {
				continue
			}
			for _, u := range rep.Updates {
				for _, c := range u.CVEs {
					if !seen[c] {
						seen[c] = true
						out = append(out, c)
					}
				}
			}
		}
	}
	return out, nil
}

// osUpdateReport returns the osupdate report of a status, or nil.
func osUpdateReport(st store.UpdateStatus) *updates.WindowsReport {
	if st.Source != updates.SourceWindows {
		return nil
	}
	var rep updates.WindowsReport
	if json.Unmarshal(st.Data, &rep) != nil || rep.Manager == "" {
		return nil
	}
	return &rep
}

// endpoints returns the approved agents of a tenant to check, with the
// newest Windows build known (agent connection or inventory). Inventories
// and update reports are read with one query each.
func (s *Server) vulnEndpoints(ctx context.Context, tenant string, agents []store.Agent) ([]vuln.Endpoint, error) {
	invs, err := s.store.ListInventories(ctx, tenant)
	if err != nil {
		return nil, err
	}
	invOf := make(map[string][]byte, len(invs))
	for _, inv := range invs {
		invOf[inv.AgentID] = inv.Data
	}
	statuses, err := s.store.ListUpdateStatus(ctx, tenant, "")
	if err != nil {
		return nil, err
	}
	osReports := map[string][]*updates.WindowsReport{}
	for _, st := range statuses {
		if rep := osUpdateReport(st); rep != nil {
			osReports[st.AgentID] = append(osReports[st.AgentID], rep)
		}
	}
	var out []vuln.Endpoint
	for _, a := range agents {
		if a.Status != store.AgentActive {
			continue
		}
		ep := vuln.Endpoint{AgentID: a.ID, Hostname: a.Host.Hostname, OS: a.Host.OS, OSVersion: a.Host.OSVersion}
		if a.Host.OS == "linux" {
			for _, rep := range osReports[a.ID] {
				for _, u := range rep.Updates {
					if len(u.CVEs) > 0 {
						ep.Packages = append(ep.Packages, vuln.PackageCVEs{Name: u.ID, Installed: u.Installed,
							Version: u.Version, Severity: u.Severity, CVEs: u.CVEs})
					}
				}
			}
		}
		if data, ok := invOf[a.ID]; ok {
			if parsed, err := inventory.Parse(data); err == nil {
				if a.Host.OS == "windows" && parsed.OS.Build != "" {
					_, cur, _ := vuln.WindowsBuild(ep.OSVersion)
					if _, rev, ok := vuln.WindowsBuild("build " + parsed.OS.Build); ok && rev > cur {
						ep.OSVersion = "build " + parsed.OS.Build
					}
				}
				if a.Host.OS == "windows" {
					pending := map[string]string{}
					for _, pu := range parsed.PendingUpdates {
						pending[strings.ToLower(pu.Name)] = pu.Version
					}
					for _, sw := range parsed.Software {
						app := vuln.InstalledApp{Name: sw.Name, Version: sw.Version, UserScope: sw.Scope == "user"}
						if sw.Scope != "user" {
							app.Pending = pending[strings.ToLower(sw.Name)]
						}
						ep.Apps = append(ep.Apps, app)
					}
				}
			}
		}
		out = append(out, ep)
	}
	return out, nil
}

// vulnMatchTTL is how long the CVEs found on a tenant's computers are
// shown without computing them again; after that the page still shows them
// while they are computed in the background.
const vulnMatchTTL = 3 * time.Minute

// vulnMatch is the last matching of a tenant.
type vulnMatch struct {
	at         time.Time
	agents     string         // the active agents it covers
	all        []vuln.Finding // read only: copy before sorting
	refreshing bool
}

// activeAgents identifies the set of active agents.
func activeAgents(agents []store.Agent) string {
	var ids []string
	for _, a := range agents {
		if a.Status == store.AgentActive {
			ids = append(ids, a.ID)
		}
	}
	sort.Strings(ids)
	return strings.Join(ids, ",")
}

// vulnFindings returns the CVEs affecting a tenant's computers and when
// they were computed. They are computed while the page waits the first
// time and when computers were added or removed; otherwise older results
// are shown while they are computed again in the background.
func (s *Server) vulnFindings(ctx context.Context, tenant string, ix *vuln.Index) ([]vuln.Finding, time.Time, error) {
	agents, err := s.store.ListAgents(ctx, tenant)
	if err != nil {
		return nil, time.Time{}, err
	}
	set := activeAgents(agents)
	s.vulns.mu.Lock()
	m := s.vulns.matched[tenant]
	if m != nil && m.agents == set {
		if time.Since(m.at) > vulnMatchTTL && !m.refreshing {
			m.refreshing = true
			go func() {
				bg, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Minute)
				defer cancel()
				if _, _, err := s.matchVulns(bg, tenant, ix, agents, set); err != nil {
					s.log.Warn("vulnerability matching", "tenant", tenant, "err", err)
					s.vulns.mu.Lock()
					m.refreshing = false
					s.vulns.mu.Unlock()
				}
			}()
		}
		s.vulns.mu.Unlock()
		return m.all, m.at, nil
	}
	s.vulns.mu.Unlock()
	return s.matchVulns(ctx, tenant, ix, agents, set)
}

func (s *Server) matchVulns(ctx context.Context, tenant string, ix *vuln.Index, agents []store.Agent, set string) ([]vuln.Finding, time.Time, error) {
	eps, err := s.vulnEndpoints(ctx, tenant, agents)
	if err != nil {
		return nil, time.Time{}, err
	}
	m := &vulnMatch{at: time.Now(), agents: set, all: ix.Match(eps)}
	s.vulns.mu.Lock()
	if s.vulns.matched == nil {
		s.vulns.matched = map[string]*vulnMatch{}
	}
	s.vulns.matched[tenant] = m
	s.vulns.mu.Unlock()
	return m.all, m.at, nil
}

// vulnData is the Vulnerabilities tab.
type vulnData struct {
	Ready     bool // sources downloaded
	Months    int
	Products  int // applications with NVD data
	HasKEV    bool
	Query     string
	Exploited bool // only exploited CVEs
	// Sort: "" (urgency: exploited first, then score), cvss, cvss_asc,
	// hosts or hosts_asc (affected computers).
	Sort       string
	Findings   []vuln.Finding
	Total      int // findings before the filter
	Shown      int
	Endpoints  int // affected endpoints
	KEVCount   int
	Critical   int
	Selected   *vuln.Finding // detail of one CVE
	ComputedAt time.Time     // when the CVEs were matched
	MaxFinding int
	// How to fix the selected CVE: the bulk action form, prepared.
	FixURL, FixLabel, FixNote string
}

const maxVulnRows = 300

func (s *Server) vulnReport(r *http.Request, tenant string) (*vulnData, error) {
	ctx := r.Context()
	q := r.URL.Query()
	d := &vulnData{Query: strings.TrimSpace(q.Get("q")), Exploited: q.Get("exploited") == "1", MaxFinding: maxVulnRows}
	switch q.Get("sort") {
	case "cvss", "cvss_asc", "hosts", "hosts_asc":
		d.Sort = q.Get("sort")
	}
	ix, err := s.vulnIndex(ctx)
	if errors.Is(err, vuln.ErrNoData) {
		return d, nil
	}
	if err != nil {
		return nil, err
	}
	d.Ready, d.Months, d.Products, d.HasKEV = true, ix.Months, ix.Products, ix.HasKEV
	cached, at, err := s.vulnFindings(ctx, tenant, ix)
	if err != nil {
		return nil, err
	}
	d.ComputedAt = at
	all := cached
	if d.Sort != "" {
		all = append([]vuln.Finding(nil), cached...)
		sortFindings(all, d.Sort)
	}
	d.Total = len(all)
	affected := map[string]bool{}
	for i := range all {
		f := &all[i]
		if f.KEV {
			d.KEVCount++
		}
		if f.CVSS >= 9 || f.Severity == "Critical" {
			d.Critical++
		}
		for _, h := range f.Hits {
			affected[h.AgentID] = true
		}
		if id := q.Get("id"); id != "" && f.ID == id {
			d.Selected = f
		}
	}
	d.Endpoints = len(affected)
	if d.Selected != nil {
		d.FixURL, d.FixLabel, d.FixNote = s.cveFix(ctx, s.lang(r), tenant, d.Selected)
	}
	for _, f := range all {
		if d.Exploited && !f.KEV && !f.Exploited {
			continue
		}
		if d.Query != "" && !contains(f.ID+" "+f.Title+" "+f.Product, d.Query) && !hitsMatch(f.Hits, d.Query) {
			continue
		}
		d.Shown++
		if len(d.Findings) < maxVulnRows {
			d.Findings = append(d.Findings, f)
		}
	}
	return d, nil
}

// sortFindings orders findings by score or by affected computers, the
// urgency order (vuln.Sort) breaking ties.
func sortFindings(fs []vuln.Finding, by string) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		switch by {
		case "cvss":
			return a.CVSS > b.CVSS
		case "cvss_asc":
			return a.CVSS < b.CVSS
		case "hosts":
			return len(a.Hits) > len(b.Hits)
		case "hosts_asc":
			return len(a.Hits) < len(b.Hits)
		}
		return false
	})
}

// SortURL is the link of a column header: descending first, then
// ascending, keeping the search.
func (d *vulnData) SortURL(col string) string {
	v := url.Values{"tab": {"cve"}, "sort": {col}}
	if d.Sort == col {
		v.Set("sort", col+"_asc")
	}
	if d.Query != "" {
		v.Set("q", d.Query)
	}
	if d.Exploited {
		v.Set("exploited", "1")
	}
	return "/reports?" + v.Encode()
}

// SortMark is the arrow of a column header.
func (d *vulnData) SortMark(col string) string {
	switch d.Sort {
	case col:
		return " ▼"
	case col + "_asc":
		return " ▲"
	}
	return ""
}

func hitsMatch(hs []vuln.Hit, q string) bool {
	for _, h := range hs {
		if contains(h.Hostname, q) || contains(h.Fix, q) {
			return true
		}
	}
	return false
}

// cvssClass is the badge class of a CVSS score.
func cvssClass(score float64) string {
	switch {
	case score >= 7:
		return "chk-failing"
	case score >= 4:
		return "chk-warning"
	}
	return ""
}

func cvssText(score float64) string {
	if score == 0 {
		return "-"
	}
	return strconv.FormatFloat(score, 'f', 1, 64)
}

// cveFix prepares the action that fixes a CVE on the computers it
// affects: the bulk form with the action open and its parameters filled
// in. note explains when there is nothing to prepare.
func (s *Server) cveFix(ctx context.Context, lang, tenant string, f *vuln.Finding) (fixURL, label, note string) {
	q := url.Values{"for": {f.ID}}
	for _, h := range f.Hits {
		q.Add("agent", h.AgentID)
	}
	switch {
	case f.Product == "Windows":
		// The security updates rather than the KB Microsoft names: on a
		// computer months behind that KB is superseded by a newer one.
		q.Set("action", updates.WindowsModule+".install")
		q["p.classifications"] = []string{"security", "critical"}
		label = tr(lang, "Installa gli aggiornamenti di sicurezza…")
	case vuln.AppByLabel(f.Product) != nil:
		// The winget ids the scans found on these computers for the
		// application (e.g. Mozilla.Firefox.it).
		app := vuln.AppByLabel(f.Product)
		// A copy in a user's profile is out of reach of winget, which runs
		// as the system account: installing the application for every user
		// replaces it (and upgrades the computers that already have it).
		userScope := false
		for _, h := range f.Hits {
			userScope = userScope || h.UserScope
		}
		if userScope && app.Winget != "" && app.ReplacesUserCopy {
			q.Set("action", updates.WingetModule+".install")
			q.Set("p.ids", app.Winget)
			return "/agents/bulk?" + q.Encode(), tr(lang, "Installa per tutto il computer con winget…"),
				tr(lang, "Installata nel profilo dell'utente: winget, che gira con l'account di sistema, non la vede e non la può aggiornare. L'installazione per tutto il computer la sostituisce al prossimo accesso dell'utente.")
		}
		var userNote string
		switch {
		case userScope && app.Mozilla:
			userNote = tr(lang, "Installata nel profilo dell'utente: winget, che gira con l'account di sistema, non la può aggiornare. Falla aggiornare all'utente (☰ → Guida → Informazioni). Non installarla per tutto il computer: la copia nel profilo resterebbe e la nuova aprirebbe un profilo vuoto (segnalibri e password restano in quello vecchio, che si riattiva da about:profiles).")
		case userScope:
			userNote = tr(lang, "Installata nel profilo dell'utente: winget, che gira con l'account di sistema, non la può aggiornare. Aggiornala dall'applicazione stessa o distribuisci la versione per tutto il computer dalla pagina Software.")
		}
		seen := map[string]bool{}
		for _, h := range f.Hits {
			list, err := s.store.ListUpdateStatus(ctx, tenant, h.AgentID)
			if err != nil {
				continue
			}
			for _, st := range list {
				if st.Source != updates.SourceWinget {
					continue
				}
				var rep updates.WingetReport
				if json.Unmarshal(st.Data, &rep) != nil {
					continue
				}
				for _, u := range rep.Upgrades {
					if app.Name.MatchString(u.Name) && !seen[u.ID] {
						seen[u.ID] = true
						q.Add("p.ids", u.ID)
					}
				}
			}
		}
		pending := 0
		for _, h := range f.Hits {
			if h.Pending != "" {
				pending++
			}
		}
		if pending > 0 {
			userNote = strings.TrimSpace(fmt.Sprintf(tr(lang, "%d computer hanno già scaricato una versione corretta: si installa quando l'utente chiude e riapre l'applicazione."), pending) + " " + userNote)
		}
		if len(seen) == 0 {
			// No winget upgrade: a package of the library, the newest,
			// deployed on the affected computers (not for a Mozilla copy in
			// a user's profile, see userNote).
			if !(userScope && app.Mozilla) {
				if pkg := s.libraryPackage(ctx, tenant, app); pkg != nil {
					dq := url.Values{}
					for _, h := range f.Hits {
						if h.Pending == "" {
							dq.Add("agent", h.AgentID)
						}
					}
					return "/packages/" + pkg.SHA256 + "/deploy?" + dq.Encode(),
						fmt.Sprintf(tr(lang, "Distribuisci %s %s dalla libreria…"), pkg.Name, pkg.Version),
						strings.TrimSpace(tr(lang, "Nessun aggiornamento winget per questa applicazione: si usa il pacchetto della libreria Software.") + " " + userNote)
				}
			}
			if userNote != "" {
				return "", "", userNote
			}
			return "", "", tr(lang, "Nessun aggiornamento winget disponibile per questa applicazione sui computer colpiti: distribuisci la nuova versione dalla pagina Software.")
		}
		// The computers with a copy in a user's profile are in the action
		// too: winget finds nothing to upgrade there, the note says why.
		q.Set("action", updates.WingetModule+".upgrade")
		label, note = tr(lang, "Aggiorna l'applicazione con winget…"), userNote
	default:
		seen := map[string]bool{}
		for _, h := range f.Hits {
			if h.Package != "" && !seen[h.Package] {
				seen[h.Package] = true
				q.Add("p.packages", h.Package)
			}
		}
		if len(seen) == 0 {
			return "", "", ""
		}
		q.Set("action", updates.OSUpdateModule+".install")
		label = tr(lang, "Aggiorna i pacchetti…")
	}
	return "/agents/bulk?" + q.Encode(), label, ""
}

// libraryPackage returns the newest package of the library for a catalog
// application: by winget id, or by the application's name.
func (s *Server) libraryPackage(ctx context.Context, tenant string, app *vuln.App) *store.Package {
	pkgs, err := s.store.ListPackages(ctx, tenant)
	if err != nil {
		return nil
	}
	var best *store.Package
	for i := range pkgs {
		p := &pkgs[i]
		if !((app.Winget != "" && strings.EqualFold(p.WingetID, app.Winget)) || app.Name.MatchString(p.Name)) {
			continue
		}
		if best == nil || vuln.CompareVersions(p.Version, best.Version) > 0 {
			best = p
		}
	}
	return best
}
