package vuln

import (
	"context"
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Microsoft security updates: one CVRF document per month. Each CVE lists,
// per product, the KB that fixes it and the build it brings (FixedBuild,
// e.g. 10.0.26100.9711); a Windows agent at an older revision of the same
// build is affected.

type msrcIndex struct {
	Value []struct {
		ID                 string    `json:"ID"`
		InitialReleaseDate time.Time `json:"InitialReleaseDate"`
		CurrentReleaseDate time.Time `json:"CurrentReleaseDate"`
		CvrfURL            string    `json:"CvrfUrl"`
	} `json:"value"`
}

type msrcText struct {
	Value string `json:"Value"`
}

type msrcDoc struct {
	Vulnerability []struct {
		CVE     string   `json:"CVE"`
		Title   msrcText `json:"Title"`
		Threats []struct {
			Type        int      `json:"Type"`
			Description msrcText `json:"Description"`
		} `json:"Threats"`
		CVSSScoreSets []struct {
			BaseScore float64 `json:"BaseScore"`
		} `json:"CVSSScoreSets"`
		Remediations []struct {
			Type        int      `json:"Type"`
			Description msrcText `json:"Description"`
			FixedBuild  string   `json:"FixedBuild"`
		} `json:"Remediations"`
		RevisionHistory []struct {
			Date string `json:"Date"`
		} `json:"RevisionHistory"`
	} `json:"Vulnerability"`
}

// Windows NT builds: 10.0.26100.9711, 6.3.9600.21000.
var fixedBuildRe = regexp.MustCompile(`^(?:10\.0|6\.[0-3])\.(\d+)\.(\d+)$`)

var severityRank = map[string]int{"Critical": 4, "Important": 3, "Moderate": 2, "Low": 1}

// parseMSRC extracts the CVEs fixed by a Windows build.
func parseMSRC(doc *msrcDoc, released time.Time) []CVE {
	var out []CVE
	for _, v := range doc.Vulnerability {
		c := CVE{ID: v.CVE, Title: v.Title.Value, Released: released}
		if !strings.HasPrefix(c.ID, "CVE-") {
			continue
		}
		seen := map[WinFix]bool{}
		for _, r := range v.Remediations {
			m := fixedBuildRe.FindStringSubmatch(strings.TrimSpace(r.FixedBuild))
			if r.Type != 2 || m == nil {
				continue
			}
			b, _ := strconv.Atoi(m[1])
			rev, _ := strconv.Atoi(m[2])
			kb := strings.TrimSpace(r.Description.Value)
			if _, err := strconv.Atoi(kb); err == nil {
				kb = "KB" + kb
			} else {
				kb = ""
			}
			fx := WinFix{Build: b, Rev: rev, KB: kb}
			if !seen[fx] {
				seen[fx] = true
				c.Fixes = append(c.Fixes, fx)
			}
		}
		if len(c.Fixes) == 0 {
			continue
		}
		for _, t := range v.Threats {
			switch t.Type {
			case 1: // exploitability: "Publicly Disclosed:No;Exploited:Yes;…"
				if strings.Contains(t.Description.Value, "Exploited:Yes") {
					c.Exploited = true
				}
			case 3: // severity
				if severityRank[t.Description.Value] > severityRank[c.Severity] {
					c.Severity = t.Description.Value
				}
			}
		}
		for _, s := range v.CVSSScoreSets {
			c.CVSS = max(c.CVSS, s.BaseScore)
		}
		sort.Slice(c.Fixes, func(i, j int) bool {
			if c.Fixes[i].Build != c.Fixes[j].Build {
				return c.Fixes[i].Build < c.Fixes[j].Build
			}
			return c.Fixes[i].Rev < c.Fixes[j].Rev
		})
		out = append(out, c)
	}
	return out
}

// refreshMSRC downloads the months not yet stored or revised since.
func (f *Fetcher) refreshMSRC(ctx context.Context) error {
	if f.fresh(ctx, "msrc-index", 12*time.Hour) {
		return nil
	}
	var idx msrcIndex
	if err := f.get(ctx, f.MSRC+"/updates", &idx); err != nil {
		return err
	}
	since := f.Now().AddDate(0, -f.Months, 0)
	for _, m := range idx.Value {
		if m.InitialReleaseDate.Before(since) || m.CvrfURL == "" {
			continue
		}
		key, version := "msrc/"+m.ID, m.CurrentReleaseDate.UTC().Format(time.RFC3339)
		if cur, err := f.Store.GetVulnFeed(ctx, key); err == nil && cur.Version == version {
			continue
		}
		var doc msrcDoc
		if err := f.get(ctx, m.CvrfURL, &doc); err != nil {
			return err
		}
		cves := parseMSRC(&doc, m.InitialReleaseDate)
		if err := f.put(ctx, key, version, cves); err != nil {
			return err
		}
		f.Log.Info("Microsoft security updates downloaded", "month", m.ID, "windows_cves", len(cves))
	}
	return f.put(ctx, "msrc-index", "", struct{}{})
}

// windowsCVEs loads the stored months, a CVE released again in a later
// month merged with its first release.
func windowsCVEs(ctx context.Context, st Store) ([]CVE, error) {
	feeds, err := st.ListVulnFeeds(ctx, "msrc/")
	if err != nil {
		return nil, err
	}
	byID := map[string]*CVE{}
	var order []string
	for _, fd := range feeds {
		var list []CVE
		if err := json.Unmarshal(fd.Data, &list); err != nil {
			continue
		}
		for _, c := range list {
			if cur, ok := byID[c.ID]; ok {
				cur.Fixes = append(cur.Fixes, c.Fixes...)
				cur.Exploited = cur.Exploited || c.Exploited
				cur.CVSS = max(cur.CVSS, c.CVSS)
				if c.Released.Before(cur.Released) {
					cur.Released = c.Released
				}
				continue
			}
			c := c
			byID[c.ID] = &c
			order = append(order, c.ID)
		}
	}
	out := make([]CVE, 0, len(order))
	for _, id := range order {
		out = append(out, *byID[id])
	}
	return out, nil
}
