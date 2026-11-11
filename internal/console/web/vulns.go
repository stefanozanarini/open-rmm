package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/console/vuln"
	"github.com/stefanozanarini/open-rmm/internal/inventory"
	"github.com/stefanozanarini/open-rmm/internal/updates"
)

// CVEs affecting the endpoints (Reporting → Vulnerabilities). The sources
// are downloaded in the background (RefreshVulns, every few hours); the
// loaded index is kept in memory for a few minutes.

// vulnCacheTTL is how long the loaded extracts are reused.
const vulnCacheTTL = 10 * time.Minute

type vulnCache struct {
	mu sync.Mutex
	ix *vuln.Index
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
// newest Windows build known (agent connection or inventory).
func (s *Server) vulnEndpoints(ctx context.Context, tenant string) ([]vuln.Endpoint, error) {
	agents, err := s.store.ListAgents(ctx, tenant)
	if err != nil {
		return nil, err
	}
	var out []vuln.Endpoint
	for _, a := range agents {
		if a.Status != store.AgentActive {
			continue
		}
		ep := vuln.Endpoint{AgentID: a.ID, Hostname: a.Host.Hostname, OS: a.Host.OS, OSVersion: a.Host.OSVersion}
		if a.Host.OS == "linux" {
			if list, err := s.store.ListUpdateStatus(ctx, tenant, a.ID); err == nil {
				for _, st := range list {
					if rep := osUpdateReport(st); rep != nil {
						for _, u := range rep.Updates {
							if len(u.CVEs) > 0 {
								ep.Packages = append(ep.Packages, vuln.PackageCVEs{Name: u.ID, Installed: u.Installed,
									Version: u.Version, Severity: u.Severity, CVEs: u.CVEs})
							}
						}
					}
				}
			}
		}
		if inv, err := s.store.GetInventory(ctx, tenant, a.ID); err == nil {
			if parsed, err := inventory.Parse(inv.Data); err == nil {
				if a.Host.OS == "windows" && parsed.OS.Build != "" {
					_, cur, _ := vuln.WindowsBuild(ep.OSVersion)
					if _, rev, ok := vuln.WindowsBuild("build " + parsed.OS.Build); ok && rev > cur {
						ep.OSVersion = "build " + parsed.OS.Build
					}
				}
				if a.Host.OS == "windows" {
					for _, sw := range parsed.Software {
						ep.Apps = append(ep.Apps, vuln.InstalledApp{Name: sw.Name, Version: sw.Version})
					}
				}
			}
		}
		out = append(out, ep)
	}
	return out, nil
}

// vulnData is the Vulnerabilities tab.
type vulnData struct {
	Ready      bool // sources downloaded
	Months     int
	Products   int // applications with NVD data
	HasKEV     bool
	Query      string
	Exploited  bool // only exploited CVEs
	Findings   []vuln.Finding
	Total      int // findings before the filter
	Shown      int
	Endpoints  int // affected endpoints
	KEVCount   int
	Critical   int
	Selected   *vuln.Finding // detail of one CVE
	MaxFinding int
	// How to fix the selected CVE: the bulk action form, prepared.
	FixURL, FixLabel, FixNote string
}

const maxVulnRows = 300

func (s *Server) vulnReport(r *http.Request, tenant string) (*vulnData, error) {
	ctx := r.Context()
	q := r.URL.Query()
	d := &vulnData{Query: strings.TrimSpace(q.Get("q")), Exploited: q.Get("exploited") == "1", MaxFinding: maxVulnRows}
	ix, err := s.vulnIndex(ctx)
	if errors.Is(err, vuln.ErrNoData) {
		return d, nil
	}
	if err != nil {
		return nil, err
	}
	d.Ready, d.Months, d.Products, d.HasKEV = true, ix.Months, ix.Products, ix.HasKEV
	eps, err := s.vulnEndpoints(ctx, tenant)
	if err != nil {
		return nil, err
	}
	all := ix.Match(eps)
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
		if len(seen) == 0 {
			return "", "", tr(lang, "Nessun aggiornamento winget disponibile per questa applicazione sui computer colpiti: distribuisci la nuova versione dalla pagina Software.")
		}
		q.Set("action", updates.WingetModule+".upgrade")
		label = tr(lang, "Aggiorna l'applicazione con winget…")
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
