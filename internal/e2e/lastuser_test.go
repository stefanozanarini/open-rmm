package e2e

import (
	"context"
	"html"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stefanozanarini/tempra-rmm/internal/console/store"
)

// The last user of a computer stays visible for the days set while nobody is
// logged on or it is offline.
func TestLastUserShown(t *testing.T) {
	e := startConsole(t)
	ctx := context.Background()
	pc := e.addWindowsAgent(t, "PC-PORTATILE") // inventory without a logged-on user, never seen online
	e.store.SetLastUser(ctx, e.tenant, pc, store.LastUser{User: `CORP\mario.rossi`, SeenAt: time.Now().Add(-3 * 24 * time.Hour), Source: store.LastUserLogon})
	c, csrf := e.login(t, admin)

	_, body := get(t, c, e.console.URL+"/agents")
	if !strings.Contains(html.UnescapeString(body), `<span class="muted" title="ultimo utente, visto il`) || !strings.Contains(body, `mario.rossi`) {
		t.Fatalf("last user not in the list: %s", body)
	}
	if _, body = get(t, c, e.console.URL+"/agents?q=mario.rossi"); !strings.Contains(body, "PC-PORTATILE") {
		t.Fatal("search by last user")
	}
	// Shorter than its age: no longer shown.
	_, body, _ = post(t, c, e.console.URL+"/settings/last-user", url.Values{"csrf": {csrf}, "last_user_days": {"2"}})
	if !strings.Contains(body, "Impostazioni salvate") {
		t.Fatalf("save setting: %s", body)
	}
	if _, body = get(t, c, e.console.URL+"/agents"); strings.Contains(body, "mario.rossi") {
		t.Fatal("last user shown after the days set")
	}
	if _, body, _ = post(t, c, e.console.URL+"/settings/last-user", url.Values{"csrf": {csrf}, "last_user_days": {"400"}}); !strings.Contains(body, "tra 1 e 90") {
		t.Fatal("out-of-range days accepted")
	}
}
