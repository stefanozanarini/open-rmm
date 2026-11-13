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

// With the Active Directory report, computers are found by the name of
// their user, and * stands for any text.
func TestSearchByUserName(t *testing.T) {
	e := startConsole(t)
	ctx := context.Background()
	pc := e.addWindowsAgent(t, "PC-CONTA01")
	e.addWindowsAgent(t, "PC-MAGAZZINO")
	e.store.SetLastUser(ctx, e.tenant, pc, store.LastUser{User: `CORP\mrossi`, SeenAt: time.Now(), Source: store.LastUserLogon})
	e.store.PutADDomain(ctx, store.ADDomain{TenantID: e.tenant, Domain: "corp.local", AgentID: pc, CollectedAt: time.Now(),
		Data: []byte(`{"schema":1,"domain":"corp.local","collected_at":"2026-11-13T10:00:00Z","computers":[],
			"users":[{"sam":"mrossi","given_name":"Mario","surname":"Rossi","display_name":"Mario Rossi"}]}`)})
	c, _ := e.login(t, admin)
	for q, want := range map[string]bool{"rossi": true, "mario+rossi": true, "mros*": true, "pc-conta*": true, "*01": true,
		"conta*": false, "bianchi": false} {
		_, body := get(t, c, e.console.URL+"/agents?q="+q)
		if got := strings.Contains(body, ">PC-CONTA01<"); got != want || strings.Contains(body, ">PC-MAGAZZINO<") {
			t.Errorf("q=%s: found=%v", q, got)
		}
		if want && !strings.Contains(body, "Mario Rossi") {
			t.Errorf("q=%s: AD name not shown", q)
		}
	}
}
