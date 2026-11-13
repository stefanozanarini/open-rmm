package e2e

import (
	"context"
	"html"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stefanozanarini/tempra-rmm/internal/console/store"
	"github.com/stefanozanarini/tempra-rmm/internal/ids"
)

func TestGroups(t *testing.T) {
	e := startConsole(t)
	pc1 := e.addWindowsAgent(t, "PC-01")
	pc2 := e.addWindowsAgent(t, "PC-02")
	pc3 := e.addWindowsAgent(t, "PC-03")
	e.store.SetLastUser(context.Background(), e.tenant, pc1, store.LastUser{User: `CORP\mario.rossi`, SeenAt: time.Now(), Source: store.LastUserLogon})
	c, csrf := e.login(t, admin)

	// A public computer group, filled by name.
	_, body, at := post(t, c, e.console.URL+"/groups", url.Values{"csrf": {csrf}, "name": {"Contabilità"}, "kind": {"computer"}, "scope": {"public"}})
	if !strings.Contains(body, "Gruppo Contabilità creato") || !strings.HasPrefix(at.Path, "/groups/") {
		t.Fatalf("create: %s %s", at, body)
	}
	pcs := at.Path
	_, body, _ = post(t, c, e.console.URL+pcs, url.Values{"csrf": {csrf}, "do": {"add"}, "names": {"pc-02\nPC-99"}})
	if !strings.Contains(body, "1 membri aggiunti") || !strings.Contains(body, "Non trovati: PC-99") || !strings.Contains(body, "PC-02") {
		t.Fatalf("add by name: %s", body)
	}
	// From the bulk actions.
	_, body, _ = post(t, c, e.console.URL+"/groups/agents", url.Values{"csrf": {csrf}, "group": {strings.TrimPrefix(pcs, "/groups/")}, "agent": {pc3}})
	if !strings.Contains(body, "1 membri aggiunti") || !strings.Contains(body, "PC-03") {
		t.Fatalf("add from bulk: %s", body)
	}
	_, body = get(t, c, e.console.URL+"/agents/bulk?group="+strings.TrimPrefix(pcs, "/groups/"))
	if body = html.UnescapeString(body); !strings.Contains(body, "Azioni sul gruppo Contabilità (2 computer)") ||
		!strings.Contains(body, `value="`+pc2+`"`) || strings.Contains(body, `value="`+pc1+`"`) {
		t.Fatalf("bulk on group: %s", body)
	}

	// A personal user group: the computers where the user was last seen.
	_, _, at = post(t, c, e.console.URL+"/groups", url.Values{"csrf": {csrf}, "name": {"Commerciali"}, "kind": {"user"}})
	users := at.Path
	_, body, _ = post(t, c, e.console.URL+users, url.Values{"csrf": {csrf}, "do": {"add"}, "names": {"Mario.Rossi"}})
	if !strings.Contains(body, "1 membri aggiunti") || !strings.Contains(body, "PC-01") {
		t.Fatalf("user group: %s", body)
	}
	_, body = get(t, c, e.console.URL+"/agents?group="+strings.TrimPrefix(users, "/groups/"))
	if !strings.Contains(body, "PC-01") || strings.Contains(body, ">PC-02<") {
		t.Fatalf("agent list by user group: %s", body)
	}
	if _, body = get(t, c, e.console.URL+"/groups"); !strings.Contains(body, "Gruppi personali") || !strings.Contains(body, "Commerciali") {
		t.Fatalf("groups page: %s", body)
	}

	// Another operator sees the public group, not the personal one.
	other := admin
	other.OID, other.Username = ids.NewUUID(), "luigi@cliente.it"
	c2, _ := e.login(t, other)
	if code, _ := get(t, c2, e.console.URL+users); code != http.StatusNotFound {
		t.Fatalf("personal group of another operator: %d", code)
	}
	if code, _ := get(t, c2, e.console.URL+pcs); code != http.StatusOK {
		t.Fatalf("public group: %d", code)
	}

	_, body, _ = post(t, c, e.console.URL+pcs, url.Values{"csrf": {csrf}, "do": {"remove"}, "member": {pc2}})
	if !strings.Contains(body, "1 membri tolti") || strings.Contains(body, ">PC-02<") {
		t.Fatalf("remove: %s", body)
	}
	_, body, _ = post(t, c, e.console.URL+pcs, url.Values{"csrf": {csrf}, "do": {"delete"}})
	if !strings.Contains(body, "Gruppo Contabilità eliminato") {
		t.Fatalf("delete: %s", body)
	}
	if code, _ := get(t, c, e.console.URL+pcs); code != http.StatusNotFound {
		t.Fatalf("deleted group: %d", code)
	}
}
