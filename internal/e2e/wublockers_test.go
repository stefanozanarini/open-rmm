package e2e

import (
	"context"
	"encoding/json"
	"html"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/updates"
)

const blockedReport = `{"managed_by":"none","updates":[],"pending_reboot":{"required":false},
 "blockers":[
  {"id":"target_release_state","severity":"limit","summary":"Versione di Windows bloccata in UpdatePolicy\\PolicyState (TargetReleaseVersion = 22H2) senza una policy che la imposti: probabilmente un residuo da rimuovere","path":"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\WindowsUpdate\\UpdatePolicy\\PolicyState\\TargetReleaseVersion","value":"22H2"},
  {"id":"service_bits","severity":"block","summary":"Servizio bits disabilitato","path":"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\bits\\Start","value":"4"}]}`

func TestWindowsUpdateBlockersAndLogs(t *testing.T) {
	e := startConsole(t)
	ctx := context.Background()
	publishTo(t, e.store, filepath.Join(repoRoot(t), "modules", "winupdate"))
	pc := e.addWindowsAgent(t, "PC-BLOCCATO")
	rep, err := updates.ParseWindows([]byte(blockedReport), time.Now())
	if err != nil || len(rep.Blockers) != 2 || rep.Blockers[0].Severity != "block" || !rep.Blocked() || !rep.Limited() {
		t.Fatalf("report = %+v, %v", rep, err)
	}
	raw, _ := json.Marshal(rep)
	e.store.PutUpdateStatus(ctx, store.UpdateStatus{TenantID: e.tenant, AgentID: pc, Source: updates.SourceWindows,
		ScannedAt: rep.ScannedAt, Data: raw, ManagedBy: "none"})
	c, csrf := e.login(t, admin)

	_, body := get(t, c, e.console.URL+"/patches?show=blocked")
	if !strings.Contains(body, "PC-BLOCCATO") || !strings.Contains(body, "con aggiornamenti bloccati da impostazioni") ||
		!strings.Contains(body, `#update-blockers">bloccato`) {
		t.Fatalf("dashboard: %s", body)
	}
	_, body = get(t, c, e.console.URL+"/agents/"+pc)
	page := html.UnescapeString(body)
	if !strings.Contains(page, "Impostazioni che limitano gli aggiornamenti") || !strings.Contains(page, `UpdatePolicy\PolicyState`) ||
		!strings.Contains(page, "Servizio bits disabilitato") {
		t.Fatalf("agent page: %s", page)
	}

	// The logs are a read-only collection: one click, no sign-in.
	_, body, _ = post(t, c, e.console.URL+"/agents/"+pc+"/collect", url.Values{"csrf": {csrf}, "module": {"winupdate"}, "action": {"logs"}})
	if !strings.Contains(body, "Raccolta avviata") {
		t.Fatalf("collect logs: %s", body)
	}
	jobs, _ := e.store.ListJobs(ctx, e.tenant, pc, 10)
	if len(jobs) != 1 || jobs[0].Module != "winupdate" || jobs[0].Action != "logs" {
		t.Fatalf("jobs = %+v", jobs)
	}
	result := `{"events":[{"time":"2026-11-01T10:00:00Z","log":"System","id":20,"level":"error","provider":"Microsoft-Windows-WindowsUpdateClient","message":"Installation Failure: 0x800f081f"}],
	 "cbs_log":["2026-11-01 10:00:01, Error CBS Failed to resolve package [HRESULT = 0x800f081f]"],"blockers":[],"services":[{"name":"bits","status":"Stopped","start_type":"Disabled"}]}`
	if err := e.store.UpdateJob(ctx, e.tenant, pc, jobs[0].ID, store.JobUpdate{State: store.JobSucceeded, Result: []byte(result), Progress: 100}, time.Now()); err != nil {
		t.Fatal(err)
	}
	_, body = get(t, c, e.console.URL+"/jobs/"+jobs[0].ID)
	if !strings.Contains(body, `<pre class="log">`) || !strings.Contains(body, "CBS_E") && !strings.Contains(body, "Failed to resolve package") ||
		!strings.Contains(body, "Log di Windows Update raccolti: 1 eventi") {
		t.Fatalf("job page: %s", body)
	}
	if _, body = get(t, c, e.console.URL+"/agents/"+pc); !strings.Contains(body, `href="/jobs/`+jobs[0].ID+`"`) {
		t.Fatal("no link to the collected logs on the agent page")
	}
}
