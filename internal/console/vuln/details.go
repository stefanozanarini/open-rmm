package vuln

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"time"
)

// Single CVEs from NVD: title and CVSS of the CVEs the Linux package
// managers name without them. Fetched a few at a time, kept for good.

// CVEDetail is what the reports show of a CVE.
type CVEDetail struct {
	Title    string    `json:"title,omitempty"`
	CVSS     float64   `json:"cvss,omitempty"`
	Released time.Time `json:"released,omitempty"`
}

// maxDetailsPerRun bounds a refresh: without an NVD key 200 requests take
// about 20 minutes.
const maxDetailsPerRun = 200

// RefreshDetails downloads the details of the CVEs in ids not yet known.
func (f *Fetcher) RefreshDetails(ctx context.Context, ids []string) error {
	known, err := cveDetails(ctx, f.Store)
	if err != nil {
		return err
	}
	done := 0
	for _, id := range ids {
		if _, ok := known[id]; ok || done >= maxDetailsPerRun {
			continue
		}
		done++
		var page nvdPage
		err := f.getWith(ctx, f.NVD+"?"+url.Values{"cveId": {id}}.Encode(), map[string]string{"apiKey": f.NVDKey}, &page)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(f.NVDPause):
		}
		if err != nil {
			return err
		}
		d := CVEDetail{}
		for _, v := range page.Vulnerabilities {
			for _, desc := range v.CVE.Descriptions {
				if desc.Lang == "en" {
					d.Title = desc.Value
					if len(d.Title) > 200 {
						d.Title = d.Title[:197] + "…"
					}
					break
				}
			}
			for _, k := range []string{"cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"} {
				for _, m := range v.CVE.Metrics[k] {
					d.CVSS = max(d.CVSS, m.CVSSData.BaseScore)
				}
				if d.CVSS > 0 {
					break
				}
			}
			if t, err := time.Parse("2006-01-02T15:04:05.000", v.CVE.Published); err == nil {
				d.Released = t
			}
		}
		// Unknown to NVD yet: stored empty, not asked again every run.
		if err := f.put(ctx, "cve/"+id, "", d); err != nil {
			return err
		}
	}
	return nil
}

func cveDetails(ctx context.Context, st Store) (map[string]CVEDetail, error) {
	feeds, err := st.ListVulnFeeds(ctx, "cve/")
	if err != nil {
		return nil, err
	}
	out := make(map[string]CVEDetail, len(feeds))
	for _, fd := range feeds {
		var d CVEDetail
		if json.Unmarshal(fd.Data, &d) == nil {
			out[strings.TrimPrefix(fd.Key, "cve/")] = d
		}
	}
	return out, nil
}
