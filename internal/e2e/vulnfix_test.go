package e2e

import (
	"context"
	"encoding/json"
	"html"
	"strings"
	"testing"
	"time"

	"github.com/stefanozanarini/tempra-rmm/internal/console/store"
	"github.com/stefanozanarini/tempra-rmm/internal/console/vuln"
	"github.com/stefanozanarini/tempra-rmm/internal/inventory"
)

// CVE page: a browser update waiting for the restart is shown as such; with
// no winget upgrade, the library package is offered for the computers.
func TestConsoleVulnPendingAndLibrary(t *testing.T) {
	e := startConsole(t)
	ctx := context.Background()
	c, _ := e.login(t, admin)
	e.store.PutVulnFeed(ctx, store.VulnFeed{Key: "msrc/2026-Oct", Data: []byte(`[]`)})
	feed := func(cpe, id, endExcl string) {
		raw, _ := json.Marshal([]vuln.AppCVE{{ID: id, Title: "test", CVSS: 9, Ranges: []vuln.VerRange{{EndExcl: endExcl}}}})
		e.store.PutVulnFeed(ctx, store.VulnFeed{Key: "nvd/" + cpe, Data: raw})
	}
	feed("microsoft:edge_chromium", "CVE-2026-90001", "141.0")
	feed("videolan:vlc_media_player", "CVE-2026-90002", "3.0.21")

	edge := e.addWindowsAgent(t, "PC-EDGE")
	inv := inventory.Inventory{Schema: 1, CollectedAt: time.Now().UTC(),
		Software:       []inventory.Software{{Name: "Microsoft Edge", Version: "140.0.3485.54", Scope: "machine"}},
		PendingUpdates: []inventory.PendingUpdate{{Name: "Microsoft Edge", Version: "142.0.3595.53"}}}
	raw, _ := json.Marshal(inv)
	e.store.PutInventory(ctx, store.Inventory{TenantID: e.tenant, AgentID: edge, Data: raw,
		Summary: store.InventorySummary{CollectedAt: inv.CollectedAt.Add(time.Second)}}, nil)
	_, body := get(t, c, e.console.URL+"/reports?tab=cve&id=CVE-2026-90001")
	if body = html.UnescapeString(body); !strings.Contains(body, "142.0.3595.53 pronto, manca il riavvio") ||
		!strings.Contains(body, "1 computer hanno già scaricato una versione corretta") {
		t.Fatalf("pending restart: %s", body)
	}

	vlc := e.addWindowsAgent(t, "PC-VLC", inventory.Software{Name: "VLC media player", Version: "3.0.18", Scope: "machine"})
	sha := strings.Repeat("ab", 32)
	e.store.PutPackage(ctx, store.Package{TenantID: e.tenant, SHA256: sha, Name: "VLC media player", Version: "3.0.21",
		FileName: "vlc-3.0.21-win64.msi", Kind: "msi", Source: "upload", CreatedAt: time.Now()})
	_, body = get(t, c, e.console.URL+"/reports?tab=cve&id=CVE-2026-90002")
	if body = html.UnescapeString(body); !strings.Contains(body, "/packages/"+sha+"/deploy?agent="+vlc) ||
		!strings.Contains(body, "Distribuisci VLC media player 3.0.21 dalla libreria") {
		t.Fatalf("library package: %s", body)
	}
}
