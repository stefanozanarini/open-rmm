package e2e

import (
	"context"
	"encoding/json"
	"html"
	"strings"
	"testing"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/console/vuln"
	"github.com/stefanozanarini/open-rmm/internal/ids"
)

// Reporting → Vulnerabilities: the CVEs of each Windows build, the
// exploited ones first, with the computers and the KB that fixes them.
func TestConsoleVulnerabilities(t *testing.T) {
	e := startConsole(t)
	ctx := context.Background()
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
			Host:         store.HostInfo{Hostname: name, OS: "windows", OSFamily: "client", OSVersion: "Windows 11 Pro 24H2 (build " + build + ")"},
			CertNotAfter: now.Add(time.Hour)})
	}

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
	_, body = get(t, c, e.console.URL+"/reports?tab=cve&q=smb")
	if strings.Contains(body, "CVE-2026-1001") || !strings.Contains(body, "CVE-2026-1002") {
		t.Fatal("search")
	}
}
