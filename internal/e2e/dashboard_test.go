package e2e

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/inventory"
	"github.com/stefanozanarini/open-rmm/internal/updates"
)

func TestConsoleDashboard(t *testing.T) {
	e := startConsole(t)
	ctx := context.Background()
	now := time.Now()
	boot := now.Add(-45 * 24 * time.Hour)
	for i, name := range []string{"PC-01", "PC-02", "PC-03"} {
		id := e.addWindowsAgent(t, name)
		e.store.UpdateAgentSeen(ctx, e.tenant, id, &store.HostInfo{Hostname: name, OS: "windows", Arch: "amd64", OSFamily: "client",
			AgentVersion: "1.0.2", OSVersion: "Windows 11"}, now, nil)
		inv := inventory.Inventory{Schema: 1, CollectedAt: now.UTC(), OS: inventory.OS{Name: "Microsoft Windows 11 Pro", DisplayVersion: "24H2", LastBoot: &boot},
			Volumes: []inventory.Volume{{Mount: "C:", SizeBytes: 100 << 30, FreeBytes: int64(5+i*20) << 30, BitLocker: []string{"on", "off", "on"}[i]}}}
		inv.Software = []inventory.Software{{Name: "7-Zip 24.08 (x64)", Version: "24.08"},
			{Name: "Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.38.33135", Version: "14.38"}}
		if i < 2 {
			inv.Software = append(inv.Software, inventory.Software{Name: []string{"Java 8 Update 401 (64-bit)", "Java 8 Update 431"}[i], Version: []string{"8.0.4010", "8.0.4310"}[i]})
		}
		if i == 0 {
			inv.Batteries = []inventory.Battery{{Name: "BAT0", DesignCapacity: 50000, FullChargeCapacity: 45000}}
		}
		raw, _ := json.Marshal(inv)
		e.store.PutInventory(ctx, store.Inventory{TenantID: e.tenant, AgentID: id, Data: raw, Summary: store.InventorySummary{CollectedAt: time.Now()}}, nil)
		rep := []byte(`{"managed_by":"none","scanned_at":"` + now.UTC().Format(time.RFC3339) + `","updates":[],"pending_reboot":{"required":false}}`)
		important := 0
		if i == 1 {
			important = 2
		}
		e.store.PutUpdateStatus(ctx, store.UpdateStatus{TenantID: e.tenant, AgentID: id, Source: updates.SourceWindows, ScannedAt: now, Data: rep,
			ManagedBy: "none", Important: important})
		e.store.PutUpdateStatus(ctx, store.UpdateStatus{TenantID: e.tenant, AgentID: id, Source: updates.SourceWinget, ScannedAt: now,
			Data: []byte(`{"scanned_at":"` + now.UTC().Format(time.RFC3339) + `","upgrades":[]}`), ThirdParty: i})
		status := store.CheckOK
		if i == 2 {
			status = store.CheckFailing
		}
		e.store.PutCheck(ctx, store.Check{TenantID: e.tenant, AgentID: id, CheckID: "protection-status/antivirus", Status: status, UpdatedAt: now})
	}
	c, _ := e.login(t, admin)
	_, body := get(t, c, e.console.URL+"/reports")
	if dir := os.Getenv("DASH_HTML"); dir != "" {
		os.WriteFile(dir, []byte(body), 0o644)
	}
	for _, want := range []string{`class="donut"`, "Tipi di dispositivo", "Portatili", "Windows 11 Pro 24H2", "30–60 giorni", "Libero: meno del 10%",
		"Non cifrato", "Assente o disattivato", `href="/patches?show=missing"`, "1.0.2",
		"Computer più indietro con gli aggiornamenti", `href="/reports?software=Java&amp;tab=computers"`, "2 versioni", "Software più installati"} {
		if !strings.Contains(body, want) {
			t.Fatalf("dashboard lacks %q: %s", want, body)
		}
	}
	if strings.Contains(body, "Visual C++") {
		t.Fatal("runtime listed among the popular software")
	}
	// PC-02: 2 Windows updates and 1 application, first among the outdated.
	if i, j := strings.Index(body, ">PC-02<"), strings.Index(body, ">PC-03<"); i < 0 || j < 0 || i > j {
		t.Fatalf("outdated order: PC-02 at %d, PC-03 at %d", i, j)
	}
	if strings.Contains(body, "style=") {
		t.Fatal("inline style: blocked by the CSP")
	}
}
