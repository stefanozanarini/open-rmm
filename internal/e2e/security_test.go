package e2e

import (
	"context"
	"fmt"
	"net/url"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/console/authn"
	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/ids"
)

// resultModule is a fake module whose action returns the given JSON.
func resultModule(t *testing.T, id, version, action, result string) string {
	m := fmt.Sprintf(`{"id":%q,"version":%q,"protocol_version":1,"entrypoints":{%q:{"type":"sh","path":"main.sh"}},"actions":{%q:{}}}`,
		id, version, platform(), action)
	return shModule(t, m, `. "$OPENRMM_MODULE_DIR/_sdk/openrmm.sh"; rmm_read_request
# The agent provides a persistent state directory to every module.
if [ -z "$OPENRMM_STATE_DIR" ] || ! touch "$OPENRMM_STATE_DIR/seen"; then rmm_error "no state directory"; exit 1; fi
rmm_result '`+result+`'`)
}

func (e *env) alerts(agentID string) map[string]store.Alert {
	as, _ := e.store.ListAlerts(context.Background(), e.tenant, agentID, true, 100)
	out := map[string]store.Alert{}
	for _, a := range as {
		out[a.Kind] = a
	}
	return out
}

func ev(rec int, at time.Time, eventID int, kind, user, ip string, logonType int) string {
	return fmt.Sprintf(`{"channel":"security","record_id":%d,"time":%q,"event_id":%d,"kind":%q,"user":%q,"source_ip":%q,"logon_type":%d}`,
		rec, at.UTC().Format(time.RFC3339), eventID, kind, user, ip, logonType)
}

func TestUnusualLogonsRaiseAlerts(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("uses the sh entrypoint")
	}
	e := start(t)
	now := time.Now()
	var events []string
	events = append(events, ev(1, now, 4624, "logon", "mario", "203.0.113.7", 10)) // RDP from the internet
	for i := range 12 {                                                            // spraying from one address
		events = append(events, ev(10+i, now, 4625, "logon_failed", fmt.Sprintf("user%d", i%6), "10.0.0.9", 3))
	}
	events = append(events, ev(40, now, 4740, "lockout", "giulia", "", 0))
	events = append(events, ev(41, now, 4624, "logon", "mario", "192.168.1.5", 10)) // allowed by default
	v1 := e.publish(t, resultModule(t, "accesslog", "1.0.0", "collect", `{"events":[`+strings.Join(events, ",")+`]}`))
	_, agentID := startAgent(t, e, true)
	if j := e.waitFinal(t, e.queue(t, agentID, v1, "collect", "{}")); j.State != store.JobSucceeded {
		t.Fatalf("job: %s %s", j.State, j.Error)
	}
	waitFor(t, func() bool { return len(e.alerts(agentID)) >= 3 })
	got := e.alerts(agentID)
	if a := got["rdp.outside_lan"]; a.Severity != store.SeverityCritical || !strings.Contains(a.Summary, "203.0.113.7") {
		t.Fatalf("RDP alert = %+v", a)
	}
	if a := got["logon.spray"]; a.Severity != store.SeverityCritical || !strings.Contains(a.Summary, "10.0.0.9") {
		t.Fatalf("spray alert = %+v", a)
	}
	if _, ok := got["account.lockout"]; !ok || len(got) != 3 {
		t.Fatalf("alerts = %+v", got)
	}
	if evs, _ := e.store.ListLogonEvents(context.Background(), e.tenant, agentID, 100); len(evs) != 15 {
		t.Fatalf("stored %d events", len(evs))
	}

	// With configured LAN subnets, RDP from another private network is unexpected too.
	if err := e.store.PutSettings(context.Background(), e.tenant, store.Settings{RDPAllowedSubnets: []string{"10.0.0.0/8"}}, "t"); err != nil {
		t.Fatal(err)
	}
	v2 := e.publish(t, resultModule(t, "accesslog", "1.0.1", "collect",
		`{"events":[`+ev(42, now, 4624, "logon", "mario", "192.168.1.6", 10)+`,`+ev(43, now, 4624, "logon", "anna", "10.1.1.1", 10)+`]}`))
	if j := e.waitFinal(t, e.queue(t, agentID, v2, "collect", "{}")); j.State != store.JobSucceeded {
		t.Fatalf("job: %s %s", j.State, j.Error)
	}
	waitFor(t, func() bool {
		as, _ := e.store.ListAlerts(context.Background(), e.tenant, agentID, true, 100)
		for _, a := range as {
			if strings.Contains(a.Summary, "192.168.1.6") {
				return true
			}
		}
		return false
	})
	as, _ := e.store.ListAlerts(context.Background(), e.tenant, agentID, true, 100)
	for _, a := range as {
		if strings.Contains(a.Summary, "10.1.1.1") {
			t.Fatalf("RDP from an allowed subnet raised %+v", a)
		}
	}
}

func TestModuleChecksAreStored(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("uses the sh entrypoint")
	}
	e := start(t)
	v := e.publish(t, resultModule(t, "trendmicro", "1.0.0", "status",
		`{"checks":[{"id":"sep","status":"failing","summary":"servizio tmlisten Stopped"},{"id":"basecamp","status":"ok","summary":"attivo"},{"id":"BAD ID","status":"ok"},{"id":"x","status":"great"}]}`))
	_, agentID := startAgent(t, e, true)
	if j := e.waitFinal(t, e.queue(t, agentID, v, "status", "{}")); j.State != store.JobSucceeded {
		t.Fatalf("job: %s %s", j.State, j.Error)
	}
	var checks []store.Check
	waitFor(t, func() bool {
		checks, _ = e.store.ListChecks(context.Background(), e.tenant, agentID)
		return len(checks) == 2
	})
	if checks[0].CheckID != "trendmicro/basecamp" || checks[1].CheckID != "trendmicro/sep" || checks[1].Status != store.CheckFailing {
		t.Fatalf("checks = %+v", checks)
	}
	waitFor(t, func() bool { _, ok := e.alerts(agentID)["check.failing"]; return ok })
	if w, _ := e.store.WorstChecks(context.Background(), e.tenant); w[agentID] != store.CheckFailing {
		t.Fatalf("worst = %+v", w)
	}
}

func TestConsoleAlertsAndSettings(t *testing.T) {
	e := startConsole(t)
	ctx := context.Background()
	e.store.SetAgentStatus(ctx, e.tenant, e.agentID, store.AgentActive)
	now := time.Now()
	e.store.RaiseAlert(ctx, store.Alert{TenantID: e.tenant, AgentID: e.agentID, Severity: store.SeverityCritical,
		Kind: "rdp.outside_lan", Summary: "Accesso RDP di CORP\\mario da 203.0.113.7", DedupeKey: "k", FirstSeen: now, LastSeen: now})
	e.store.PutCheck(ctx, store.Check{TenantID: e.tenant, AgentID: e.agentID, CheckID: "trendmicro/sep", Status: store.CheckFailing,
		Summary: "servizio tmlisten Stopped", UpdatedAt: now})
	e.store.AddLogonEvents(ctx, e.tenant, e.agentID, []store.LogonEvent{{Channel: "security", RecordID: 1, At: now,
		EventID: 4624, Kind: "logon", User: "mario", Domain: "CORP", LogonType: 10, SourceIP: "203.0.113.7"}}, now)

	// A reader sees alerts but cannot take them in charge or change settings.
	reader := admin
	reader.OID, reader.Roles = ids.NewUUID(), []string{authn.RoleReader}
	rc, rcsrf := e.login(t, reader)
	_, body := get(t, rc, e.console.URL+"/alerts")
	if !strings.Contains(body, "203.0.113.7") || strings.Contains(body, "Prendi in carico") || !strings.Contains(body, `sev-critical">1<`) {
		t.Fatalf("alerts page for reader: %s", body)
	}
	alerts, _ := e.store.ListAlerts(ctx, e.tenant, "", true, 10)
	if code, _, _ := post(t, rc, e.console.URL+"/alerts/"+alerts[0].ID+"/ack", url.Values{"csrf": {rcsrf}}); code != 403 {
		t.Fatalf("reader ack: %d", code)
	}
	if code, _ := get(t, rc, e.console.URL+"/settings"); code != 403 {
		t.Fatalf("reader settings: %d", code)
	}

	c, csrf := e.login(t, admin)
	_, body = get(t, c, e.console.URL+"/agents/"+e.agentID)
	for _, want := range []string{"trendmicro/sep", "servizio tmlisten Stopped", "Avvisi aperti", "desktop remoto", `CORP\mario`} {
		if !strings.Contains(body, want) {
			t.Errorf("agent page lacks %q", want)
		}
	}
	if _, body = get(t, c, e.console.URL+"/agents"); !strings.Contains(body, "chk-failing") {
		t.Error("agents list lacks the check status")
	}
	_, body, u := post(t, c, e.console.URL+"/alerts/"+alerts[0].ID+"/ack", url.Values{"csrf": {csrf}, "return": {"/agents/" + e.agentID}})
	if u.Path != "/agents/"+e.agentID || !strings.Contains(body, "preso in carico") {
		t.Fatalf("ack redirect %s", u)
	}
	if open, _ := e.store.ListAlerts(ctx, e.tenant, "", true, 10); len(open) != 0 {
		t.Fatal("alert still open")
	}

	_, body, _ = post(t, c, e.console.URL+"/settings", url.Values{"csrf": {csrf}, "rdp_subnets": {"192.168.10.0/24\n10.20.0.0/16\n172.16.5.4"}})
	if !strings.Contains(body, "Impostazioni salvate") {
		t.Fatalf("save settings: %s", body)
	}
	if s, _ := e.store.GetSettings(ctx, e.tenant); strings.Join(s.RDPAllowedSubnets, " ") != "192.168.10.0/24 10.20.0.0/16 172.16.5.4/32" {
		t.Fatalf("settings = %+v", s)
	}
	_, body, _ = post(t, c, e.console.URL+"/settings", url.Values{"csrf": {csrf}, "rdp_subnets": {"192.168.10.0/99"}})
	if !strings.Contains(body, "Subnet non valida") {
		t.Fatal("invalid subnet accepted")
	}
	if s, _ := e.store.GetSettings(ctx, e.tenant); len(s.RDPAllowedSubnets) != 3 {
		t.Fatal("invalid input changed the settings")
	}
}
