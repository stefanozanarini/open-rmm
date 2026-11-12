package web

import (
	"testing"

	"github.com/stefanozanarini/tempra-rmm/internal/console/vuln"
)

func TestSortFindings(t *testing.T) {
	fs := []vuln.Finding{
		{CVE: vuln.CVE{ID: "a", CVSS: 5}, Hits: make([]vuln.Hit, 3)},
		{CVE: vuln.CVE{ID: "b", CVSS: 9.8}, Hits: make([]vuln.Hit, 1)},
		{CVE: vuln.CVE{ID: "c", CVSS: 7}, Hits: make([]vuln.Hit, 10)},
	}
	order := func() string {
		s := ""
		for _, f := range fs {
			s += f.ID
		}
		return s
	}
	for by, want := range map[string]string{"cvss": "bca", "cvss_asc": "acb", "hosts": "cab", "hosts_asc": "bac"} {
		sortFindings(fs, by)
		if got := order(); got != want {
			t.Errorf("%s: %s, want %s", by, got, want)
		}
	}
	d := &vulnData{Sort: "hosts", Query: "chrome", Exploited: true}
	if got := d.SortURL("hosts"); got != "/reports?exploited=1&q=chrome&sort=hosts_asc&tab=cve" {
		t.Errorf("SortURL = %s", got)
	}
	if d.SortMark("hosts") != " ▼" || d.SortMark("cvss") != "" {
		t.Error("SortMark")
	}
}
