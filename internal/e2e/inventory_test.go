package e2e

import (
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/ids"
	"github.com/stefanozanarini/open-rmm/internal/inventory"
	"github.com/stefanozanarini/open-rmm/internal/policy"
)

func (e *env) inventory(agentID string) (store.Inventory, error) {
	return e.store.GetInventory(context.Background(), e.tenant, agentID)
}

func TestInventoryFromPolicy(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("uses the sh entrypoint")
	}
	fastPolicies(t)
	e := start(t)
	v := e.publish(t, filepath.Join(repoRoot(t), "modules", "inventory"))
	_, agentID := startAgent(t, e, true)
	e.publishPolicy(t, &policy.Policy{ID: ids.NewUUID(), TenantID: e.tenant, Name: "Inventario", Version: 1,
		AppliesTo: policy.AppliesAll, Rules: []policy.Rule{ruleFor(v, "inventory", inventory.Action, nil)}})
	waitForWithin(t, func() bool { _, err := e.inventory(agentID); return err == nil }, 20*time.Second)
	got, _ := e.inventory(agentID)
	inv, err := inventory.Parse(got.Data)
	if err != nil {
		t.Fatal(err)
	}
	if inv.OS.Name == "" || len(inv.CPUs) == 0 || inv.Memory.TotalBytes == 0 {
		t.Fatalf("inventory = %+v", inv)
	}
}

const fakeInventoryManifest = `{"id":"ID","version":"VERSION","protocol_version":1,
 "entrypoints":{"PLATFORM":{"type":"sh","path":"main.sh"}},"actions":{"collect":{}}}`

func fakeInventoryModule(t *testing.T, id, version, software string) string {
	m := strings.NewReplacer("ID", id, "VERSION", version, "PLATFORM", platform()).Replace(fakeInventoryManifest)
	return shModule(t, m, `. "$OPENRMM_MODULE_DIR/_sdk/openrmm.sh"; rmm_read_request
rmm_result "{\"schema\":1,\"collected_at\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"system\":{\"model\":\"Latitude 5440\"},\"remote_access\":{\"supremo_id\":\"123 456 789\"},\"software\":[`+software+`]}"`)
}

func TestInventoryChangesAreRecorded(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("uses the sh entrypoint")
	}
	e := start(t)
	v1 := e.publish(t, fakeInventoryModule(t, "inventory", "1.0.0", `{\"name\":\"7-Zip\",\"version\":\"23.01\"}`))
	v2 := e.publish(t, fakeInventoryModule(t, "inventory", "1.0.1",
		`{\"name\":\"7-Zip\",\"version\":\"24.08\"},{\"name\":\"Firefox\",\"version\":\"131\"}`))
	_, agentID := startAgent(t, e, true)

	if j := e.waitFinal(t, e.queue(t, agentID, v1, "collect", "{}")); j.State != store.JobSucceeded {
		t.Fatalf("first inventory: %s %s", j.State, j.Error)
	}
	waitFor(t, func() bool { _, err := e.inventory(agentID); return err == nil })
	first, err := e.inventory(agentID)
	if err != nil || first.Summary.SupremoID != "123456789" || first.Summary.Model != "Latitude 5440" {
		t.Fatalf("first inventory = %+v, %v", first.Summary, err)
	}
	time.Sleep(1100 * time.Millisecond) // collected_at has a one-second resolution
	if j := e.waitFinal(t, e.queue(t, agentID, v2, "collect", "{}")); j.State != store.JobSucceeded {
		t.Fatalf("second inventory: %s %s", j.State, j.Error)
	}
	var changes []store.InventoryChange
	waitFor(t, func() bool {
		changes, _ = e.store.ListInventoryChanges(context.Background(), e.tenant, agentID, 10)
		return len(changes) >= 2
	})
	kinds := map[string]string{}
	for _, c := range changes {
		kinds[c.Kind] = c.Detail
	}
	if !strings.Contains(kinds[inventory.ChangeSoftwareUpdated], "23.01 → 24.08") ||
		!strings.Contains(kinds[inventory.ChangeSoftwareAdded], "Firefox") || len(changes) != 2 {
		t.Fatalf("changes = %+v", changes)
	}
}

// Only results of the inventory module are inventories: another module
// returning the same shape does not overwrite the inventory.
func TestOnlyInventoryModuleFeedsInventory(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("uses the sh entrypoint")
	}
	e := start(t)
	v := e.publish(t, fakeInventoryModule(t, "lookalike", "1.0.0", ""))
	_, agentID := startAgent(t, e, true)
	if j := e.waitFinal(t, e.queue(t, agentID, v, "collect", "{}")); j.State != store.JobSucceeded {
		t.Fatalf("job: %s %s", j.State, j.Error)
	}
	time.Sleep(300 * time.Millisecond) // results are processed after the job is stored
	if _, err := e.inventory(agentID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("inventory from another module: %v", err)
	}
}

func TestConsoleShowsInventoryAndFamilies(t *testing.T) {
	e := startConsole(t)
	ctx := context.Background()
	srv := ids.NewUUID()
	e.store.CreateAgent(ctx, store.Agent{TenantID: e.tenant, ID: srv, Status: store.AgentActive,
		Host:            store.HostInfo{Hostname: "srv01", OS: "windows", Arch: "amd64", OSFamily: "server"},
		CertFingerprint: "fp2", CertNotAfter: time.Now().Add(time.Hour)})
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "internal", "inventory", "testdata", "windows.json"))
	if err != nil {
		t.Fatal(err)
	}
	inv, err := inventory.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.store.PutInventory(ctx, store.Inventory{TenantID: e.tenant, AgentID: srv, Data: raw,
		Summary: store.InventorySummary{CollectedAt: inv.CollectedAt, Model: inv.System.Model, SupremoID: inv.RemoteAccess.SupremoID}},
		[]store.InventoryChange{{At: inv.CollectedAt, Kind: inventory.ChangeSoftwareAdded, Detail: "Firefox 131"}}); err != nil {
		t.Fatal(err)
	}
	c, _ := e.login(t, admin)
	base := e.console.URL + "/agents"
	if _, body := get(t, c, base); !strings.Contains(body, "Tutti (2)") || !strings.Contains(body, "Server (1)") || !strings.Contains(body, "Client (0)") {
		t.Fatal("wrong counts")
	}
	if _, body := get(t, c, base+"?family=server"); !strings.Contains(body, "srv01") || strings.Contains(body, "pc01") {
		t.Fatal("server section wrong")
	}
	if _, body := get(t, c, base+"?family=client"); strings.Contains(body, "srv01") {
		t.Fatal("server listed among clients")
	}
	if _, body := get(t, c, base+"?q="+url.QueryEscape("123456789")); !strings.Contains(body, "srv01") || strings.Contains(body, ">pc01<") {
		t.Fatal("search by Supremo id failed")
	}
	_, body := get(t, c, base+"/"+srv)
	for _, want := range []string{"ThinkPad T14 Gen 3", "123456789", "XTS-AES-256", "Google Chrome", "Firefox 131", "software installato"} {
		if !strings.Contains(body, want) {
			t.Errorf("agent page lacks %q", want)
		}
	}
}
