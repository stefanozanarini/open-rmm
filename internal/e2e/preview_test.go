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
	data, _ := json.Marshal(inv)
	var changes []store.InventoryChange
	if i == 0 {
		changes = []store.InventoryChange{
			{At: inv.CollectedAt, Kind: inventory.ChangeSoftwareUpdated, Detail: "Google Chrome: 128.0.6613.138 → 129.0.6668.90"},
			{At: inv.CollectedAt, Kind: inventory.ChangeHardware, Detail: "memoria: 8.0 GiB → 16.0 GiB"},
		}
	}
	e.store.PutInventory(context.Background(), store.Inventory{TenantID: e.tenant, AgentID: agentID, Data: data,
		Summary: store.InventorySummary{CollectedAt: inv.CollectedAt, Manufacturer: inv.System.Manufacturer, Model: inv.System.Model,
			Serial: inv.System.Serial, LoggedOnUser: inv.OS.LoggedOnUser, SupremoID: inv.RemoteAccess.SupremoID}}, changes)
}
