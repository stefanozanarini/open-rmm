package e2e

import (
	"context"
	"encoding/json"
	"html"
	"strings"
	"testing"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/inventory"
)

func TestConsoleReports(t *testing.T) {
	e := startConsole(t)
	ctx := context.Background()
	pc1 := e.addWindowsAgent(t, "PC-01", inventory.Software{Name: "7-Zip 23.01 (x64)", Version: "23.01", Scope: "machine"})
	e.addWindowsAgent(t, "PC-02", inventory.Software{Name: "7-Zip 24.08 (x64)", Version: "24.08", Scope: "machine"},
		inventory.Software{Name: "=HYPERLINK(\"x\")", Version: "1"})
	e.addWindowsAgent(t, "PC-03", inventory.Software{Name: "Notepad++", Version: "8.6"})
	// PC-01 runs Windows 11 23H2.
	inv := inventory.Inventory{Schema: 1, CollectedAt: time.Now().UTC(), OS: inventory.OS{Name: "Microsoft Windows 11 Pro", DisplayVersion: "23H2", Build: "22631.4460"},
		Software: []inventory.Software{{Name: "7-Zip 23.01 (x64)", Version: "23.01"}}}
	raw, _ := json.Marshal(inv)
	e.store.PutInventory(ctx, store.Inventory{TenantID: e.tenant, AgentID: pc1, Data: raw,
		Summary: store.InventorySummary{CollectedAt: inv.CollectedAt, LoggedOnUser: "VW\\mrossi"}}, nil)
	e.store.AddLogonEvents(ctx, e.tenant, pc1, []store.LogonEvent{{Channel: "security", RecordID: 1, At: time.Now().Add(-time.Hour),
		EventID: 4624, Kind: "remote", User: "mrossi", Domain: "VW", LogonType: 10, SourceIP: "10.0.0.5", Status: "success"}}, time.Now())

	c, _ := e.login(t, admin)
	_, body := get(t, c, e.console.URL+"/reports?tab=computers&software=7-zip")
	body = html.UnescapeString(body)
	if !strings.Contains(body, "2 computer.") || !strings.Contains(body, "PC-01") || !strings.Contains(body, "PC-02") || strings.Contains(body, "PC-03") {
		t.Fatalf("software search: %s", body)
	}
	if _, body = get(t, c, e.console.URL+"/reports?tab=computers&software=7-zip&version=24"); !strings.Contains(body, "1 computer.") || strings.Contains(body, "PC-01") {
		t.Fatalf("version filter: %s", body)
	}
	if _, body = get(t, c, e.console.URL+"/reports?tab=computers&os=11+pro+23h2"); !strings.Contains(body, "PC-01") || strings.Contains(body, "PC-02") {
		t.Fatalf("os filter: %s", body)
	}
	if _, body = get(t, c, e.console.URL+"/reports?tab=os"); !strings.Contains(body, "Microsoft Windows 11 Pro 23H2 (22631.4460)") {
		t.Fatalf("os report: %s", body)
	}
	_, csv := get(t, c, e.console.URL+"/reports?tab=computers&software=hyperlink&format=csv")
	if !strings.HasPrefix(csv, "computer,site,") || !strings.Contains(csv, `'=HYPERLINK`) {
		t.Fatalf("csv: %q", csv)
	}
	if _, body = get(t, c, e.console.URL+"/reports?tab=logons&logon_user=ross"); !strings.Contains(body, "1 accessi.") || !strings.Contains(body, "10.0.0.5") {
		t.Fatalf("logons: %s", body)
	}
	if _, body = get(t, c, e.console.URL+"/reports?tab=logons&logon_user=nobody"); !strings.Contains(body, "0 accessi.") {
		t.Fatal("logon filter ignored")
	}
}
