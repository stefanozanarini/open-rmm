package web

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/console/vuln"
	"github.com/stefanozanarini/open-rmm/internal/inventory"
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
	err := vuln.NewFetcher(s.store, s.log).Refresh(ctx)
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
		if a.Host.OS == "windows" {
			if inv, err := s.store.GetInventory(ctx, tenant, a.ID); err == nil {
				if parsed, err := inventory.Parse(inv.Data); err == nil && parsed.OS.Build != "" {
					_, cur, _ := vuln.WindowsBuild(ep.OSVersion)
					if _, rev, ok := vuln.WindowsBuild("build " + parsed.OS.Build); ok && rev > cur {
						ep.OSVersion = "build " + parsed.OS.Build
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
	d.Ready, d.Months, d.HasKEV = true, ix.Months, ix.HasKEV
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
