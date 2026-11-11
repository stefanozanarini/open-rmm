package vuln

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/console/store"
)

func TestRefreshAndMatch(t *testing.T) {
	var srv *httptest.Server
	hits := 0
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		switch r.URL.Path {
		case "/msrc/updates":
			json.NewEncoder(w).Encode(map[string]any{"value": []map[string]any{
				{"ID": "2026-Oct", "InitialReleaseDate": "2026-10-13T07:00:00Z", "CurrentReleaseDate": "2026-11-03T00:00:00Z", "CvrfUrl": srv.URL + "/msrc/cvrf/2026-Oct"},
				{"ID": "2026-Nov", "InitialReleaseDate": "2026-11-10T07:00:00Z", "CurrentReleaseDate": "2026-11-10T00:00:00Z", "CvrfUrl": srv.URL + "/msrc/cvrf/2026-Nov"},
				{"ID": "2016-Jan", "InitialReleaseDate": "2016-01-12T07:00:00Z", "CurrentReleaseDate": "2016-01-12T00:00:00Z", "CvrfUrl": srv.URL + "/msrc/cvrf/2016-Jan"},
			}})
		case "/msrc/cvrf/2026-Oct", "/msrc/cvrf/2026-Nov":
			b, _ := os.ReadFile("testdata/msrc-" + strings.TrimPrefix(r.URL.Path, "/msrc/cvrf/") + ".json")
			w.Write(b)
		case "/nvd":
			if r.URL.Query().Get("virtualMatchString") != "cpe:2.3:a:7-zip:7-zip" {
				io.WriteString(w, `{"totalResults":0,"resultsPerPage":0,"vulnerabilities":[]}`)
				return
			}
			io.WriteString(w, `{"totalResults":2,"resultsPerPage":2,"vulnerabilities":[
			  {"cve":{"id":"CVE-2026-14266","vulnStatus":"Analyzed","published":"2026-07-29T18:16:50.720",
			    "descriptions":[{"lang":"en","value":"7-Zip XZ Decompression Heap-based Buffer Overflow"}],
			    "metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":7.8}}]},
			    "configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:*:*:*","versionEndExcluding":"26.02"}]}]}]}},
			  {"cve":{"id":"CVE-2020-0001","vulnStatus":"Rejected","published":"2020-01-01T00:00:00.000","descriptions":[],"metrics":{},
			    "configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:7-zip:7-zip:9.20:*:*:*:*:*:*:*"}]}]}]}}]}`)
		case "/kev":
			io.WriteString(w, `{"vulnerabilities":[{"cveID":"CVE-2026-1001","dateAdded":"2026-10-20","knownRansomwareCampaignUse":"Known"}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	st := store.NewMemory()
	f := NewFetcher(st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	f.MSRC, f.KEV, f.NVD, f.NVDPause = srv.URL+"/msrc", srv.URL+"/kev", srv.URL+"/nvd", 0
	f.Now = func() time.Time { return time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC) }
	ctx := context.Background()
	if err := f.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	// Nothing changed: no new download.
	before := hits
	if err := f.Refresh(ctx); err != nil || hits != before {
		t.Fatalf("second refresh downloaded again: %d → %d, %v", before, hits, err)
	}
	ix, err := Load(ctx, st)
	if err != nil || ix.Months != 2 || !ix.HasKEV {
		t.Fatalf("index: %+v %v", ix, err)
	}
	got := ix.Match([]Endpoint{
		{AgentID: "a", Hostname: "PC-OLD", OS: "windows", OSVersion: "Windows 11 Pro 24H2 (build 26100.9500)"},
		{AgentID: "b", Hostname: "PC-OCT", OS: "windows", OSVersion: "Windows 11 Pro 24H2 (build 26100.9711)"},
		{AgentID: "c", Hostname: "PC-NEW", OS: "windows", OSVersion: "Windows 11 Pro 24H2 (build 26100.9800)"},
		{AgentID: "d", Hostname: "PC-23H2", OS: "windows", OSVersion: "Windows 11 Pro 23H2 (build 22631.7000)"},
		{AgentID: "e", Hostname: "SRV-LINUX", OS: "linux", OSVersion: "Ubuntu 24.04"},
		{AgentID: "f", Hostname: "PC-ZIP", OS: "windows", Apps: []InstalledApp{{Name: "7-Zip 24.07 (x64)", Version: "24.07"}}},
		{AgentID: "g", Hostname: "PC-ZIPNEW", OS: "windows", Apps: []InstalledApp{{Name: "7-Zip 26.02 (x64)", Version: "26.02"}}},
	})
	ids := []string{}
	for _, f := range got {
		ids = append(ids, f.ID)
	}
	// KEV first, then CVSS.
	if strings.Join(ids, ",") != "CVE-2026-1001,CVE-2026-1002,CVE-2026-14266,CVE-2026-2001" {
		t.Fatalf("findings = %v", ids)
	}
	k := got[0]
	if !k.KEV || !k.Ransomware || !k.Exploited || k.Severity != "Important" || len(k.Hits) != 2 ||
		k.Hits[0].Hostname != "PC-23H2" || k.Hits[0].Fix != "KB5126653 (22631.7652)" || k.Hits[1].Hostname != "PC-OLD" {
		t.Fatalf("kev finding = %+v", k)
	}
	// Fixed in October for 26100: the November release does not count again.
	smb := got[1]
	if len(smb.Hits) != 1 || smb.Hits[0].Hostname != "PC-OLD" || smb.Hits[0].Fix != "KB5127648 (26100.9711)" || smb.CVSS != 9.8 {
		t.Fatalf("smb finding = %+v", smb)
	}
	zip := got[2]
	if zip.Product != "7-Zip" || len(zip.Hits) != 1 || zip.Hits[0].Hostname != "PC-ZIP" || zip.Hits[0].Fix != "7-Zip 26.02" ||
		zip.Hits[0].Installed != "7-Zip 24.07" {
		t.Fatalf("7-zip finding = %+v", zip)
	}
	if len(got[3].Hits) != 2 {
		t.Fatalf("november finding = %+v", got[3])
	}
}

func TestWindowsBuild(t *testing.T) {
	if b, r, ok := WindowsBuild("Windows Server 2019 Standard (build 17763.8146)"); !ok || b != 17763 || r != 8146 {
		t.Fatal(b, r, ok)
	}
	if _, _, ok := WindowsBuild("Ubuntu 24.04.5 LTS"); ok {
		t.Fatal("linux parsed as a Windows build")
	}
}

func TestCompareVersions(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{{"23.01", "24.07", -1}, {"0.81.0.0", "0.81", 0}, {"130.0.6723.117", "130.0.6723.58", 1}, {"24.2.5.2", "24.2.5", 1},
		{"2.6.12", "2.6.9", 1}, {"1.0beta", "1.0", -1}, {"24.004.20220", "24.002.21005", 1}} {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%s, %s) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestAppVersion(t *testing.T) {
	for name, want := range map[[2]string]string{
		{"7-Zip 24.07 (x64)", "24.07"}:               "7-Zip 24.07",
		{"Google Chrome", "130.0.6723.117"}:          "Google Chrome 130.0.6723.117",
		{"OpenVPN 2.5.8-I604 amd64", "2.5.040"}:      "OpenVPN 2.5.8",
		{"Zoom Workplace (64-bit)", "6.2.5 (47302)"}: "Zoom Workplace 6.2.5",
		{"Python 3.12.4 (64-bit)", "3.12.4150.0"}:    "Python 3.12.4",
		{"Microsoft Visual C++ 2015", "14.0"}:        "",
		{"Mozilla Firefox (x64 it)", "132.0.1"}:      "Mozilla Firefox 132.0.1",
		{"Mozilla Firefox ESR (x64 it)", "128.4.0"}:  "Mozilla Firefox ESR 128.4.0",
	} {
		app, v, ok := appVersion(InstalledApp{Name: name[0], Version: name[1]})
		got := ""
		if ok {
			got = app.Label + " " + v
		}
		if got != want {
			t.Errorf("%v: %q, want %q", name, got, want)
		}
	}
}

func TestRefreshDetails(t *testing.T) {
	asked := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked++
		if r.URL.Query().Get("cveId") != "CVE-2026-89156" {
			io.WriteString(w, `{"totalResults":0,"resultsPerPage":0,"vulnerabilities":[]}`)
			return
		}
		io.WriteString(w, `{"totalResults":1,"resultsPerPage":1,"vulnerabilities":[{"cve":{"id":"CVE-2026-89156","published":"2026-09-01T10:00:00.000",
		  "descriptions":[{"lang":"en","value":"PCRE2 heap overflow"}],"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":8.1}}]}}}]}`)
	}))
	defer srv.Close()
	st := store.NewMemory()
	f := NewFetcher(st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	f.NVD, f.NVDPause = srv.URL, 0
	ctx := context.Background()
	ids := []string{"CVE-2026-89156", "CVE-2026-00001"}
	if err := f.RefreshDetails(ctx, ids); err != nil || asked != 2 {
		t.Fatalf("refresh: %v, %d requests", err, asked)
	}
	// Known ones, also those NVD does not have yet, are not asked again.
	if err := f.RefreshDetails(ctx, ids); err != nil || asked != 2 {
		t.Fatalf("asked again: %d", asked)
	}
	ix, err := Load(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	got := ix.Match([]Endpoint{{AgentID: "x", Hostname: "SRV", OS: "linux",
		Packages: []PackageCVEs{{Name: "libpcre2-8-0", Installed: "10.42-1", Version: "10.42-2", Severity: "Important", CVEs: []string{"CVE-2026-89156"}}}}})
	if len(got) != 1 || got[0].CVSS != 8.1 || got[0].Title != "PCRE2 heap overflow" || got[0].Hits[0].Fix != "libpcre2-8-0 10.42-2" {
		t.Fatalf("findings = %+v", got)
	}
}
