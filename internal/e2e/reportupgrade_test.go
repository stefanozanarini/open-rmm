package e2e

import (
	"context"
	"html"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stefanozanarini/tempra-rmm/internal/console/store"
	"github.com/stefanozanarini/tempra-rmm/internal/inventory"
	"github.com/stefanozanarini/tempra-rmm/internal/updates"
)

// Reporting → Computers filtered by software offers the winget upgrade of
// that application on the computers found.
func TestConsoleReportUpgrade(t *testing.T) {
	e := startConsole(t)
	ctx := context.Background()
	publishTo(t, e.store, filepath.Join(repoRoot(t), "modules", "winget"))
	c, _ := e.login(t, admin)
	now := time.Now()
	old := e.addWindowsAgent(t, "PC-OLD", inventory.Software{Name: "Google Chrome", Version: "134.0.6998.166"})
	e.addWindowsAgent(t, "PC-USER", inventory.Software{Name: "Google Chrome", Version: "134.0.6998.166", Scope: "user"})
	e.store.PutUpdateStatus(ctx, store.UpdateStatus{TenantID: e.tenant, AgentID: old, Source: updates.SourceWinget, ScannedAt: now,
		Data: []byte(`{"scanned_at":"` + now.UTC().Format(time.RFC3339) + `","upgrades":[{"name":"Google Chrome","id":"Google.Chrome","version":"134.0.6998.166","available":"157.0.8103.50"}]}`)})
	_, body := get(t, c, e.console.URL+"/reports?tab=computers&software=chrome")
	body = html.UnescapeString(body)
	if !strings.Contains(body, "Aggiorna questa applicazione") || !strings.Contains(body, "aggiornabile con winget su 1 dei computer trovati") ||
		!strings.Contains(body, "p.ids=Google.Chrome") || !strings.Contains(body, "agent="+old) {
		t.Fatalf("upgrade button: %s", body)
	}
	if _, body = get(t, c, e.console.URL+"/reports?tab=computers&software=firefox"); strings.Contains(body, "Aggiorna questa applicazione") {
		t.Fatal("button without a match")
	}
	// Search with no filter lists every computer, with the chosen columns,
	// also in the CSV.
	_, body = get(t, c, e.console.URL+"/reports?tab=computers&search=1&col=agent_version")
	if !strings.Contains(body, "PC-OLD") || !strings.Contains(body, "PC-USER") || !strings.Contains(body, "<th>Versione agente</th>") {
		t.Fatalf("all computers with a column: %s", body)
	}
	if _, csv := get(t, c, e.console.URL+"/reports?tab=computers&search=1&col=agent_version&format=csv"); !strings.HasPrefix(csv, "computer,site,operating_system,model,user,software,version,inventory,agent_version") {
		t.Fatalf("csv: %s", csv)
	}
}
