package e2e

import (
	"context"
	"encoding/json"
	"html"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/console/signer"
	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/console/vuln"
	"github.com/stefanozanarini/open-rmm/internal/console/web"
	"github.com/stefanozanarini/open-rmm/internal/ids"
	"github.com/stefanozanarini/open-rmm/internal/inventory"
	"github.com/stefanozanarini/open-rmm/internal/updates"
)

// Reporting → Vulnerabilities: the CVEs of each Windows build, the
// exploited ones first, with the computers and the KB that fixes them.
func TestConsoleVulnerabilities(t *testing.T) {
	e := startConsole(t, func(cfg *web.Config, _ *signer.Server, _ string) {
		cfg.ModuleBundle = web.ModuleBundle{Dir: filepath.Join("..", "..", "modules")}
	})
	ctx := context.Background()
	for _, m := range []string{"winupdate", "winget", "osupdate"} {
		publishTo(t, e.store, filepath.Join(repoRoot(t), "modules", m))
	}
	c, _ := e.login(t, admin)
	if _, body := get(t, c, e.console.URL+"/reports?tab=cve"); !strings.Contains(body, "non ancora scaricati") {
		t.Fatalf("no data yet: %s", body)
	}
	cves := []vuln.CVE{
		{ID: "CVE-2026-1001", Title: "Windows Kernel Elevation of Privilege", CVSS: 7.8, Severity: "Important",
			Fixes: []vuln.WinFix{{Build: 26100, Rev: 9711, KB: "KB5127648"}}},
		{ID: "CVE-2026-1002", Title: "Windows SMB Remote Code Execution", CVSS: 9.8, Severity: "Critical",
			Fixes: []vuln.WinFix{{Build: 26100, Rev: 9600, KB: "KB5126000"}}},
	}
	raw, _ := json.Marshal(cves)
	e.store.PutVulnFeed(ctx, store.VulnFeed{Key: "msrc/2026-Oct", Data: raw})
	e.store.PutVulnFeed(ctx, store.VulnFeed{Key: "kev", Data: []byte(`{"CVE-2026-1001":{"added":"2026-10-20"}}`)})
	now := time.Now()
	for name, build := range map[string]string{"PC-OLD": "26100.9500", "PC-MID": "26100.9650", "PC-NEW": "26100.9711"} {
		id := ids.NewUUID()
		e.store.CreateAgent(ctx, store.Agent{TenantID: e.tenant, ID: id, Status: store.AgentActive, CertFingerprint: id,
			Host:         store.HostInfo{Hostname: name, OS: "windows", Arch: "amd64", OSFamily: "client", OSVersion: "Windows 11 Pro 24H2 (build " + build + ")"},
			CertNotAfter: now.Add(time.Hour)})
	}

	apps, _ := json.Marshal([]vuln.AppCVE{{ID: "CVE-2026-14266", Title: "7-Zip XZ Decompression Heap-based Buffer Overflow", CVSS: 7.8,
		Ranges: []vuln.VerRange{{EndExcl: "26.02"}}}})
	e.store.PutVulnFeed(ctx, store.VulnFeed{Key: "nvd/7-zip:7-zip", Data: apps})
	zip := e.addWindowsAgent(t, "PC-ZIP", inventory.Software{Name: "7-Zip 24.07 (x64)", Version: "24.07"})
	e.store.PutUpdateStatus(ctx, store.UpdateStatus{TenantID: e.tenant, AgentID: zip, Source: updates.SourceWinget, ScannedAt: now,
		Data: []byte(`{"scanned_at":"` + now.UTC().Format(time.RFC3339) + `","upgrades":[{"name":"7-Zip 24.07 (x64)","id":"7zip.7zip","version":"24.07","available":"26.02"}]}`)})

	// Linux: the CVEs of a pending security update, with NVD's details.
	lx := ids.NewUUID()
	e.store.CreateAgent(ctx, store.Agent{TenantID: e.tenant, ID: lx, Status: store.AgentActive, CertFingerprint: lx,
		Host: store.HostInfo{Hostname: "SRV-UBUNTU", OS: "linux", Arch: "amd64", OSFamily: "server", OSVersion: "Ubuntu 24.04.5 LTS"}, CertNotAfter: now.Add(time.Hour)})
	e.store.PutUpdateStatus(ctx, store.UpdateStatus{TenantID: e.tenant, AgentID: lx, Source: updates.SourceWindows, ScannedAt: now, ManagedBy: "none",
		Data: []byte(`{"manager":"apt","managed_by":"none","scanned_at":"` + now.UTC().Format(time.RFC3339) + `","updates":[
		  {"id":"libpcre2-8-0","title":"libpcre2-8-0 10.42-4ubuntu2.2","classification":"security","installed":"10.42-4ubuntu2.1","version":"10.42-4ubuntu2.2","cves":["CVE-2026-89156"]}]}`)})
	e.store.PutVulnFeed(ctx, store.VulnFeed{Key: "cve/CVE-2026-89156", Data: []byte(`{"title":"PCRE2 heap overflow","cvss":8.1}`)})

	_, body := get(t, c, e.console.URL+"/reports?tab=cve")
	body = html.UnescapeString(body)
	kev, smb := strings.Index(body, "CVE-2026-1001"), strings.Index(body, "CVE-2026-1002")
	if kev < 0 || smb < 0 || kev > smb || !strings.Contains(body, ">KEV<") || !strings.Contains(body, "KB5127648 (26100.9711)") {
		t.Fatalf("ranking (exploited first): %s", body)
	}
	_, body = get(t, c, e.console.URL+"/reports?tab=cve&id=CVE-2026-1001")
	body = html.UnescapeString(body)
	if !strings.Contains(body, "Computer colpiti (2)") || !strings.Contains(body, "PC-OLD") || !strings.Contains(body, "PC-MID") ||
		strings.Contains(body, "PC-NEW") || !strings.Contains(body, "sfruttata attivamente (CISA KEV)") {
		t.Fatalf("detail: %s", body)
	}
	_, body = get(t, c, e.console.URL+"/reports?tab=cve&id=CVE-2026-14266")
	if body = html.UnescapeString(body); !strings.Contains(body, "PC-ZIP") || !strings.Contains(body, "7-Zip 24.07") || !strings.Contains(body, "7-Zip 26.02") {
		t.Fatalf("application detail: %s", body)
	}
	_, body = get(t, c, e.console.URL+"/reports?tab=cve&id=CVE-2026-89156")
	if body = html.UnescapeString(body); !strings.Contains(body, "SRV-UBUNTU") || !strings.Contains(body, "libpcre2-8-0 10.42-4ubuntu2.2") ||
		!strings.Contains(body, "PCRE2 heap overflow") || !strings.Contains(body, "CVSS 8.1") {
		t.Fatalf("linux detail: %s", body)
	}
	// Fixing: the bulk form, opened on the action with its parameters.
	fixLink := regexp.MustCompile(`href="(/agents/bulk\?[^"]+)"`)
	for id, want := range map[string][]string{
		"CVE-2026-1001":  {`name="p.classifications" value="security" checked`, `name="p.classifications" value="critical" checked`, "PC-MID, PC-OLD"},
		"CVE-2026-14266": {">7zip.7zip</textarea>", "PC-ZIP"},
		"CVE-2026-89156": {">libpcre2-8-0</textarea>", "SRV-UBUNTU"},
	} {
		_, page := get(t, c, e.console.URL+"/reports?tab=cve&id="+id)
		m := fixLink.FindStringSubmatch(page)
		if m == nil {
			t.Fatalf("%s: no fix link: %s", id, page)
		}
		_, form := get(t, c, e.console.URL+html.UnescapeString(m[1]))
		form = html.UnescapeString(form)
		if !strings.Contains(form, `<details class="action" open>`) || !strings.Contains(form, id) {
			t.Fatalf("%s: action not prepared: %s", id, form)
		}
		for _, w := range want {
			if !strings.Contains(form, w) {
				t.Fatalf("%s: form lacks %q: %s", id, w, form)
			}
		}
	}
	if _, form := get(t, c, e.console.URL+"/agents/bulk?agent="+zip+"&action=winupdate.install&p.classifications=security"); !strings.Contains(html.UnescapeString(form), `value="rollup">`) {
		t.Fatal("unlisted classification still checked")
	}

	_, body = get(t, c, e.console.URL+"/reports?tab=cve&q=smb")
	if strings.Contains(body, "CVE-2026-1001") || !strings.Contains(body, "CVE-2026-1002") {
		t.Fatal("search")
	}
}
