package e2e

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/ids"
)

// The alerts badge of an agent opens the alerts of that computer only.
func TestConsoleAlertsOfOneAgent(t *testing.T) {
	e := startConsole(t)
	ctx := context.Background()
	a1, a2 := e.addWindowsAgent(t, "PC-UNO"), e.addWindowsAgent(t, "PC-DUE")
	now := time.Now()
	for agent, summary := range map[string]string{a1: "64 accessi falliti da 10.0.0.1", a2: "13 accessi falliti da 10.0.0.2"} {
		if _, err := e.store.RaiseAlert(ctx, store.Alert{TenantID: e.tenant, ID: ids.NewUUID(), AgentID: agent, Severity: store.SeverityWarning,
			Kind: "logon_failures", Summary: summary, DedupeKey: agent, FirstSeen: now, LastSeen: now}); err != nil {
			t.Fatal(err)
		}
	}
	c, csrf := e.login(t, admin)
	if _, body := get(t, c, e.console.URL+"/agents"); !strings.Contains(body, `href="/alerts?agent=`+a1+`"`) {
		t.Fatal("alerts badge not filtered by agent")
	}
	_, body := get(t, c, e.console.URL+"/alerts?agent="+a1)
	if !strings.Contains(body, "Avvisi di PC-UNO") || !strings.Contains(body, "10.0.0.1") || strings.Contains(body, "10.0.0.2") ||
		!strings.Contains(body, `href="/alerts?agent=`+a1+`&amp;all=1"`) && !strings.Contains(body, `href="/alerts?all=1&amp;agent=`+a1+`"`) {
		t.Fatalf("filtered alerts: %s", body)
	}
	// Acknowledging comes back to the filtered list.
	alerts, _ := e.store.ListAlerts(ctx, e.tenant, a1, true, 10)
	_, _, final := post(t, c, e.console.URL+"/alerts/"+alerts[0].ID+"/ack", url.Values{"csrf": {csrf}, "return": {"/alerts?agent=" + a1}})
	if final.RequestURI() != "/alerts?agent="+a1 {
		t.Fatalf("after ack at %s", final)
	}
	if _, body = get(t, c, e.console.URL+"/alerts"); !strings.Contains(body, "10.0.0.2") || strings.Contains(body, "Avvisi di") {
		t.Fatal("unfiltered list")
	}
}
