package e2e

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stefanozanarini/tempra-rmm/internal/console/store"
	"github.com/stefanozanarini/tempra-rmm/internal/inventory"
)

// The summary shows model and serial number; for Dell the Service Tag with
// a link to Dell's support page.
func TestConsoleSerialNumber(t *testing.T) {
	e := startConsole(t)
	ctx := context.Background()
	c, _ := e.login(t, admin)
	for name, sys := range map[string]inventory.System{
		"PC-DELL": {Manufacturer: "Dell Inc.", Model: "Dell Pro 14 PC14250", Serial: "ABC1234"},
		"PC-HP":   {Manufacturer: "HP", Model: "EliteBook 840 G9", Serial: "5CG1234XYZ"},
	} {
		id := e.addWindowsAgent(t, name)
		inv := inventory.Inventory{Schema: 1, CollectedAt: time.Now().UTC(), System: sys}
		raw, _ := json.Marshal(inv)
		e.store.PutInventory(ctx, store.Inventory{TenantID: e.tenant, AgentID: id, Data: raw,
			Summary: store.InventorySummary{CollectedAt: inv.CollectedAt.Add(time.Second), Serial: sys.Serial}}, nil)
		_, body := get(t, c, e.console.URL+"/agents?agent="+id+"&tab=summary")
		if !strings.Contains(body, sys.Model) || !strings.Contains(body, "<code>"+sys.Serial+"</code>") {
			t.Fatalf("%s: summary without model or serial: %s", name, body)
		}
		dell := strings.Contains(body, "Service Tag") && strings.Contains(body, "dell.com/support/home/product-support/servicetag/"+sys.Serial)
		if dell != (name == "PC-DELL") {
			t.Fatalf("%s: Service Tag shown = %v", name, dell)
		}
	}
}
