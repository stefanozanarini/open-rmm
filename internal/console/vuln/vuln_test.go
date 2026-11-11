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
		case "/kev":
			io.WriteString(w, `{"vulnerabilities":[{"cveID":"CVE-2026-1001","dateAdded":"2026-10-20","knownRansomwareCampaignUse":"Known"}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	st := store.NewMemory()
	f := NewFetcher(st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	f.MSRC, f.KEV = srv.URL+"/msrc", srv.URL+"/kev"
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
	})
	ids := []string{}
	for _, f := range got {
		ids = append(ids, f.ID)
	}
	// KEV first, then CVSS.
	if strings.Join(ids, ",") != "CVE-2026-1001,CVE-2026-1002,CVE-2026-2001" {
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
	if len(got[2].Hits) != 2 {
		t.Fatalf("november finding = %+v", got[2])
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
