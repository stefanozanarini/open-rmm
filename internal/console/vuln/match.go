package vuln

import (
	"context"
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"time"
)

// CISA Known Exploited Vulnerabilities: CVEs exploited in the wild.

type kevCatalog struct {
	Vulnerabilities []struct {
		CVE        string `json:"cveID"`
		Added      string `json:"dateAdded"`
		Ransomware string `json:"knownRansomwareCampaignUse"`
	} `json:"vulnerabilities"`
}

// KEV is an entry of the catalog.
type KEV struct {
	Added      string `json:"added"`
	Ransomware bool   `json:"ransomware,omitempty"`
}

func (f *Fetcher) refreshKEV(ctx context.Context) error {
	if f.fresh(ctx, "kev", 24*time.Hour) {
		return nil
	}
	var cat kevCatalog
	if err := f.get(ctx, f.KEV, &cat); err != nil {
		return err
	}
	out := make(map[string]KEV, len(cat.Vulnerabilities))
	for _, v := range cat.Vulnerabilities {
		out[v.CVE] = KEV{Added: v.Added, Ransomware: v.Ransomware == "Known"}
	}
	return f.put(ctx, "kev", "", out)
}

// Endpoint is an agent to check.
type Endpoint struct {
	AgentID, Hostname string
	OS                string // windows, linux
	OSVersion         string // e.g. Windows 11 Pro 25H2 (build 26200.9711)
}

// Hit is an endpoint affected by a CVE.
type Hit struct {
	AgentID, Hostname string
	Installed         string // e.g. 26200.9711
	Fix               string // e.g. KB5127648 (26200.9746)
}

// Finding is a CVE with the endpoints it affects.
type Finding struct {
	CVE
	Product    string
	KEV        bool
	KEVAdded   string
	Ransomware bool
	Hits       []Hit
}

// Index holds the loaded extracts.
type Index struct {
	LoadedAt time.Time
	// Windows: per build, the CVEs with the lowest fixing revision.
	win map[int][]winEntry
	kev map[string]KEV
	// Months of Microsoft data and whether the catalog is there.
	Months int
	HasKEV bool
}

type winEntry struct {
	cve *CVE
	fix WinFix
}

// Load reads the extracts. With nothing downloaded yet it returns
// ErrNoData.
func Load(ctx context.Context, st Store) (*Index, error) {
	cves, err := windowsCVEs(ctx, st)
	if err != nil {
		return nil, err
	}
	ix := &Index{LoadedAt: time.Now(), win: map[int][]winEntry{}, kev: map[string]KEV{}}
	if feeds, err := st.ListVulnFeeds(ctx, "msrc/"); err == nil {
		ix.Months = len(feeds)
	}
	if fd, err := st.GetVulnFeed(ctx, "kev"); err == nil && json.Unmarshal(fd.Data, &ix.kev) == nil {
		ix.HasKEV = true
	}
	for i := range cves {
		c := &cves[i]
		lowest := map[int]WinFix{}
		for _, fx := range c.Fixes {
			if cur, ok := lowest[fx.Build]; !ok || fx.Rev < cur.Rev {
				lowest[fx.Build] = fx
			}
		}
		for b, fx := range lowest {
			ix.win[b] = append(ix.win[b], winEntry{cve: c, fix: fx})
		}
	}
	if ix.Months == 0 && !ix.HasKEV {
		return ix, ErrNoData
	}
	return ix, nil
}

var buildRe = regexp.MustCompile(`build (\d+)\.(\d+)`)

// WindowsBuild reads build and revision from an agent's OS version.
func WindowsBuild(osVersion string) (build, rev int, ok bool) {
	m := buildRe.FindStringSubmatch(osVersion)
	if m == nil {
		return 0, 0, false
	}
	build, _ = strconv.Atoi(m[1])
	rev, _ = strconv.Atoi(m[2])
	return build, rev, true
}

// Match returns the CVEs affecting the endpoints, the most urgent first:
// exploited in the wild (CISA), exploited (vendor), then by CVSS and by
// endpoints affected.
func (ix *Index) Match(eps []Endpoint) []Finding {
	byID := map[string]*Finding{}
	add := func(c *CVE, product string, h Hit) {
		f, ok := byID[c.ID]
		if !ok {
			k, isKEV := ix.kev[c.ID]
			f = &Finding{CVE: *c, Product: product, KEV: isKEV, KEVAdded: k.Added, Ransomware: k.Ransomware}
			f.Fixes = nil
			byID[c.ID] = f
		}
		f.Hits = append(f.Hits, h)
	}
	for _, ep := range eps {
		if ep.OS != "windows" {
			continue
		}
		b, rev, ok := WindowsBuild(ep.OSVersion)
		if !ok {
			continue
		}
		for _, e := range ix.win[b] {
			if rev < e.fix.Rev {
				fix := strconv.Itoa(b) + "." + strconv.Itoa(e.fix.Rev)
				if e.fix.KB != "" {
					fix = e.fix.KB + " (" + fix + ")"
				}
				add(e.cve, "Windows", Hit{AgentID: ep.AgentID, Hostname: ep.Hostname,
					Installed: strconv.Itoa(b) + "." + strconv.Itoa(rev), Fix: fix})
			}
		}
	}
	out := make([]Finding, 0, len(byID))
	for _, f := range byID {
		sort.Slice(f.Hits, func(i, j int) bool { return f.Hits[i].Hostname < f.Hits[j].Hostname })
		out = append(out, *f)
	}
	Sort(out)
	return out
}

// Sort orders findings by urgency.
func Sort(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.KEV != b.KEV {
			return a.KEV
		}
		if a.Exploited != b.Exploited {
			return a.Exploited
		}
		if a.CVSS != b.CVSS {
			return a.CVSS > b.CVSS
		}
		if len(a.Hits) != len(b.Hits) {
			return len(a.Hits) > len(b.Hits)
		}
		return a.ID > b.ID
	})
}

// FixList returns the distinct fixes of the hits, e.g. the KBs to install.
func (f Finding) FixList() []string {
	seen := map[string]bool{}
	var out []string
	for _, h := range f.Hits {
		if h.Fix != "" && !seen[h.Fix] {
			seen[h.Fix] = true
			out = append(out, h.Fix)
		}
	}
	sort.Strings(out)
	return out
}
