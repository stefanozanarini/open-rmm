package e2e

import (
	"context"
	"encoding/json"
	"html"
	"strings"
	"testing"
	"time"

	"github.com/stefanozanarini/tempra-rmm/internal/console/store"
	"github.com/stefanozanarini/tempra-rmm/internal/inventory"
)

// On a domain controller the summary shows the domain's privileged groups
// with the members that are not standard, instead of local administrators.
func TestConsoleDCPrivilegedGroups(t *testing.T) {
	e := startConsole(t)
	ctx := context.Background()
	c, _ := e.login(t, admin)
	id := e.addWindowsAgent(t, "SRV-DC01")
	inv := inventory.Inventory{Schema: 1, CollectedAt: time.Now().UTC(),
		LocalAdmins: []inventory.LocalAccount{{Name: `ELCHO\Administrator`, Type: "user", Scope: "domain"}},
		PrivilegedGroups: []inventory.PrivilegedGroup{
			{Name: "Administrators", SID: "S-1-5-32-544", Members: []inventory.GroupMember{
				{Name: `ELCHO\Administrator`, Type: "user", Standard: true},
				{Name: `ELCHO\Domain Admins`, Type: "group", Standard: true},
				{Name: `ELCHO\SQLService`, Type: "user"},
				{Name: `ELCHO\j.kim`, Type: "user", Disabled: true}}},
			{Name: "Backup Operators", SID: "S-1-5-32-551"}}}
	raw, _ := json.Marshal(inv)
	e.store.PutInventory(ctx, store.Inventory{TenantID: e.tenant, AgentID: id, Data: raw,
		Summary: store.InventorySummary{CollectedAt: inv.CollectedAt.Add(time.Second)}}, nil)
	_, body := get(t, c, e.console.URL+"/agents?agent="+id+"&tab=summary")
	body = html.UnescapeString(body)
	if !strings.Contains(body, "Gruppi privilegiati del dominio") || !strings.Contains(body, "2 non predefiniti") ||
		!strings.Contains(body, `ELCHO\SQLService <span class="badge chk-warning">non predefinito`) ||
		strings.Contains(body, "Backup Operators") || strings.Contains(body, "Amministratori locali") {
		t.Fatalf("privileged groups: %s", body)
	}
}
