package e2e

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/console/audit"
	"github.com/stefanozanarini/open-rmm/internal/console/authn"
	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/console/web"
	"github.com/stefanozanarini/open-rmm/internal/ids"
	"github.com/stefanozanarini/open-rmm/internal/inventory"
	"github.com/stefanozanarini/open-rmm/internal/updates"
)

// TestPreview serves the console with a fake identity provider and sample
// data, for looking at the UI in a browser. It runs only on request:
//
//	OPENRMM_PREVIEW=1 go test -run Preview -timeout 0 ./internal/e2e/
//
// then open http://127.0.0.1:18080.
func TestPreview(t *testing.T) {
	if os.Getenv("OPENRMM_PREVIEW") == "" {
		t.Skip("set OPENRMM_PREVIEW=1")
	}
	e := startConsole(t)
	e.idp.signIn(admin)
	ctx := context.Background()
	now := time.Now()
	seen := now.Add(-40 * time.Second)
	for i, h := range []string{"PC-AMMIN-01", "PC-AMMIN-02", "SRV-FILE01", "PC-MAGAZZINO"} {
		id := ids.NewUUID()
		e.store.CreateAgent(ctx, store.Agent{TenantID: e.tenant, ID: id, Status: store.AgentActive,
			Host: store.HostInfo{Hostname: h, OS: "windows", Arch: "amd64", OSVersion: []string{"Windows 11 Pro 24H2 (build 26100.6584)", "Windows 11 Pro 24H2 (build 26100.6584)", "Windows Server 2022 Standard (build 20348.4171)", "Windows 10 Pro 22H2 (build 19045.6332)"}[i], AgentVersion: "0.1.0",
				OSFamily: []string{"client", "client", "server", "client"}[i]},
			CertFingerprint: "fp", CertNotAfter: now.Add(80 * 24 * time.Hour), ApprovedAt: &now, ApprovedBy: "operator:mario@cliente.it"})
		e.store.UpdateAgentSeen(ctx, e.tenant, id, nil, seen, nil)
		previewInventory(t, e, id, i)
		if i == 0 {
			j := ids.NewUUID()
			e.store.CreateJob(ctx, store.Job{TenantID: e.tenant, ID: j, AgentID: id, Module: "sysinfo", ModuleVersion: "1.0.0",
				Action: "info", Params: []byte("{}"), Envelope: []byte("x"), CreatedBy: "operator:mario@cliente.it", ExpiresAt: now.Add(time.Hour)})
			e.store.UpdateJob(ctx, e.tenant, id, j, store.JobUpdate{State: store.JobSucceeded, Progress: 100,
				Result: []byte(`{"hostname":"PC-AMMIN-01","os":"Microsoft Windows 11 Pro","os_build":"26100","uptime_seconds":86400}`)}, now)
		}
	}
	publishTo(t, e.store, filepath.Join(repoRoot(t), "modules", "script"))
	publishTo(t, e.store, filepath.Join(repoRoot(t), "modules", "software"))
	e.store.PutSite(ctx, store.Site{TenantID: e.tenant, ID: ids.NewUUID(), Name: "Bologna", Subnets: []string{"192.168.1.0/24"}})
	e.store.PutSite(ctx, store.Site{TenantID: e.tenant, ID: ids.NewUUID(), Name: "Milano", Subnets: []string{"10.20.0.0/16"}})
	e.store.AppendAudit(ctx, audit.Event{TenantID: e.tenant, Actor: "agent:x", Action: "agent.enrolled", Target: e.agentID,
		Details: map[string]any{"hostname": "pc01"}})

	cfgV := e.idp.srv.URL
	v, err := authn.NewVerifier(ctx, authn.Config{Issuer: cfgV, ClientID: "console-app", MFAClaim: "amr",
		TenantMap: map[string][]string{e.idp.tid: {e.tenant}}, MaxAuthAge: 10 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	ws, err := web.New(web.Config{Store: e.store, Verifier: v, Signer: e.signer, PublicURL: "http://127.0.0.1:18080",
		ClientSecret: "secret", Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), HTTPClient: http.DefaultClient})
	if err != nil {
		t.Fatal(err)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:18080")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("console preview on http://127.0.0.1:18080")
	srv := &http.Server{Handler: ws.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go srv.Serve(lis)
	time.Sleep(20 * time.Minute)
	srv.Close()
}

func previewInventory(t *testing.T, e *consoleEnv, agentID string, i int) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "internal", "inventory", "testdata", "windows.json"))
	if err != nil {
		t.Fatal(err)
	}
	inv, _ := inventory.Parse(raw)
	models := []string{"ThinkPad T14 Gen 3", "Latitude 5440", "PowerEdge R650", "Aspire TC-1780"}
	makers := []string{"LENOVO", "Dell Inc.", "Dell Inc.", "Acer"}
	inv.System.Model, inv.System.Manufacturer = models[i], makers[i]
	inv.OS.LoggedOnUser = []string{`CORP\mario`, `CORP\giulia`, "", `CORP\magazzino`}[i]
	if i == 3 {
		inv.Network[0].IPv4 = []string{"10.20.3.15"}
	}
	data, _ := json.Marshal(inv)
	var changes []store.InventoryChange
	if i == 0 {
		changes = []store.InventoryChange{
			{At: inv.CollectedAt, Kind: inventory.ChangeSoftwareUpdated, Detail: "Google Chrome: 128.0.6613.138 → 129.0.6668.90"},
			{At: inv.CollectedAt, Kind: inventory.ChangeHardware, Detail: "memoria: 8.0 GiB → 16.0 GiB"},
		}
	}
	ctx, now := context.Background(), time.Now()
	status := []string{store.CheckOK, store.CheckFailing, store.CheckOK, store.CheckWarning}[i]
	e.store.PutCheck(ctx, store.Check{TenantID: e.tenant, AgentID: agentID, CheckID: "trendmicro/sep", Status: status,
		Summary: map[string]string{store.CheckOK: "Trend Micro Standard Endpoint Protection 14.0.12 attivo",
			store.CheckFailing: "Trend Micro Standard Endpoint Protection 14.0.12: servizio tmlisten Stopped",
			store.CheckWarning: "Trend Micro Standard Endpoint Protection 14.0.12 attivo"}[status], UpdatedAt: now})
	e.store.PutCheck(ctx, store.Check{TenantID: e.tenant, AgentID: agentID, CheckID: "protection-status/firewall",
		Status: status, Summary: "Windows Firewall attivo su tutti i profili", UpdatedAt: now})
	if i == 0 {
		e.store.AddLogonEvents(ctx, e.tenant, agentID, []store.LogonEvent{
			{Channel: "security", RecordID: 1, At: now.Add(-2 * time.Hour), EventID: 4624, Kind: "logon", User: "mario", Domain: "CORP", LogonType: 2},
			{Channel: "security", RecordID: 2, At: now.Add(-time.Hour), EventID: 4624, Kind: "logon", User: "mario", Domain: "CORP", LogonType: 10, SourceIP: "203.0.113.7"},
			{Channel: "security", RecordID: 3, At: now.Add(-50 * time.Minute), EventID: 4625, Kind: "logon_failed", User: "admin", LogonType: 3, SourceIP: "10.0.0.9", Status: "0xc000006d 0xc000006a"},
		}, now)
		e.store.RaiseAlert(ctx, store.Alert{TenantID: e.tenant, AgentID: agentID, Severity: store.SeverityCritical, Kind: "rdp.outside_lan",
			Summary: `Accesso RDP di CORP\mario da 203.0.113.7, fuori dalle reti consentite`, DedupeKey: "a", FirstSeen: now.Add(-time.Hour), LastSeen: now.Add(-time.Hour)})
	}
	if i == 1 {
		e.store.RaiseAlert(ctx, store.Alert{TenantID: e.tenant, AgentID: agentID, Severity: store.SeverityWarning, Kind: "check.failing",
			Summary: "Controllo trendmicro/sep non superato: servizio tmlisten Stopped", DedupeKey: "b", FirstSeen: now, LastSeen: now})
	}
	winRaw := []string{windowsReport(now.Add(-70 * 24 * time.Hour)), `{"managed_by":"none","updates":[]}`,
		`{"managed_by":"wsus","wsus_server":"http://wsus01:8530","updates":[]}`, windowsReport(now.Add(-20 * 24 * time.Hour))}[i]
	if wr, err := updates.ParseWindows([]byte(winRaw), now); err == nil {
		sum := wr.Summarize(now)
		b, _ := json.Marshal(wr)
		e.store.PutUpdateStatus(ctx, store.UpdateStatus{TenantID: e.tenant, AgentID: agentID, Source: "windows", ScannedAt: wr.ScannedAt,
			Data: b, ManagedBy: wr.ManagedBy, Important: sum.Important, Other: sum.Other, OldestDays: sum.OldestDays, Behind: sum.Behind,
			Reboot: sum.Reboot, RebootSince: sum.RebootSince})
	}
	if i != 2 {
		wg, _ := updates.ParseWinget([]byte(wingetReport), now)
		b, _ := json.Marshal(wg)
		e.store.PutUpdateStatus(ctx, store.UpdateStatus{TenantID: e.tenant, AgentID: agentID, Source: "winget", ScannedAt: wg.ScannedAt,
			Data: b, ThirdParty: len(wg.Upgrades)})
	}
	e.store.PutInventory(context.Background(), store.Inventory{TenantID: e.tenant, AgentID: agentID, Data: data,
		Summary: store.InventorySummary{CollectedAt: inv.CollectedAt, Manufacturer: inv.System.Manufacturer, Model: inv.System.Model,
			Serial: inv.System.Serial, LoggedOnUser: inv.OS.LoggedOnUser, SupremoID: inv.RemoteAccess.SupremoID, IPv4: inv.IPv4()}}, changes)
	if i == 0 {
		e.store.AddNote(ctx, store.Note{TenantID: e.tenant, ID: ids.NewUUID(), AgentID: agentID, Author: "Mario Rossi (mario@cliente.it)",
			Body: "Portatile del responsabile amministrativo. Sostituita la batteria a settembre."})
	}
}
