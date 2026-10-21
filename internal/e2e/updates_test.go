package e2e

import (
	"context"
	"encoding/json"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/ids"
	"github.com/stefanozanarini/open-rmm/internal/updates"
)

func windowsReport(released time.Time) string {
	return `{"managed_by":"none","scanned_at":"` + time.Now().UTC().Format(time.RFC3339) + `","updates":[
	 {"id":"u1","title":"2025-10 Cumulative Update for Windows 11 (KB5066835)","kbs":["KB5066835"],"classification":"security","severity":"Critical","released":"` + released.UTC().Format(time.RFC3339) + `"},
	 {"id":"u2","title":"Security Intelligence Update for Microsoft Defender","kbs":["KB2267602"],"classification":"definition"}],
	 "pending_reboot":{"required":true,"reasons":["windows_update"],"since":"` + time.Now().Add(-72*time.Hour).UTC().Format(time.RFC3339) + `"},
	 "checks":[{"id":"updates","status":"failing","summary":"1 aggiornamenti di sicurezza mancanti"}]}`
}

const wingetReport = `{"upgrades":[{"name":"Mozilla Firefox","id":"Mozilla.Firefox","version":"130.0","available":"131.0.2","source":"winget"},
 {"name":"Google Chrome","id":"Google.Chrome","version":"129.0","available":"130.0","source":"winget"}]}`

func TestUpdateReportsAreStored(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("uses the sh entrypoint")
	}
	e := start(t)
	wu := e.publish(t, resultModule(t, "winupdate", "1.0.0", "scan", windowsReport(time.Now().Add(-60*24*time.Hour))))
	wg := e.publish(t, resultModule(t, "winget", "1.0.0", "scan", wingetReport))
	_, agentID := startAgent(t, e, true)
	for _, v := range []string{e.queue(t, agentID, wu, "scan", "{}"), e.queue(t, agentID, wg, "scan", "{}")} {
		if j := e.waitFinal(t, v); j.State != store.JobSucceeded {
			t.Fatalf("job: %s %s", j.State, j.Error)
		}
	}
	var list []store.UpdateStatus
	waitFor(t, func() bool {
		list, _ = e.store.ListUpdateStatus(context.Background(), e.tenant, agentID)
		return len(list) == 2
	})
	win, wgt := list[0], list[1]
	if win.Source != "windows" || win.Important != 1 || win.Other != 1 || win.Behind < 1 || !win.Reboot || win.RebootSince == nil {
		t.Fatalf("windows status = %+v", win)
	}
	if wgt.ThirdParty != 2 {
		t.Fatalf("winget status = %+v", wgt)
	}
	waitFor(t, func() bool {
		cs, _ := e.store.ListChecks(context.Background(), e.tenant, agentID)
		return len(cs) == 1 && cs[0].CheckID == "winupdate/updates"
	})
}

func TestConsolePatchDashboard(t *testing.T) {
	e := startConsole(t)
	ctx := context.Background()
	now := time.Now()
	put := func(name, family, winRaw string, wingetRaw string) string {
		id := ids.NewUUID()
		e.store.CreateAgent(ctx, store.Agent{TenantID: e.tenant, ID: id, Status: store.AgentActive, CertFingerprint: id,
			Host: store.HostInfo{Hostname: name, OS: "windows", OSFamily: family}, CertNotAfter: now.Add(time.Hour)})
		if winRaw != "" {
			r, err := updates.ParseWindows([]byte(winRaw), now)
			if err != nil {
				t.Fatal(err)
			}
			s := r.Summarize(now)
			b, _ := json.Marshal(r)
			e.store.PutUpdateStatus(ctx, store.UpdateStatus{TenantID: e.tenant, AgentID: id, Source: "windows", ScannedAt: r.ScannedAt,
				Data: b, ManagedBy: r.ManagedBy, Important: s.Important, Other: s.Other, OldestDays: s.OldestDays, Behind: s.Behind,
				Reboot: s.Reboot, RebootSince: s.RebootSince})
		}
		if wingetRaw != "" {
			r, _ := updates.ParseWinget([]byte(wingetRaw), now)
			b, _ := json.Marshal(r)
			e.store.PutUpdateStatus(ctx, store.UpdateStatus{TenantID: e.tenant, AgentID: id, Source: "winget", ScannedAt: r.ScannedAt,
				Data: b, ThirdParty: len(r.Upgrades)})
		}
		return id
	}
	behind := put("PC-BEHIND", "client", windowsReport(now.Add(-90*24*time.Hour)), wingetReport)
	put("PC-OK", "client", `{"managed_by":"none","updates":[]}`, `{"upgrades":[{"name":"Mozilla Firefox","id":"Mozilla.Firefox","version":"130","available":"131.0.2"}]}`)
	put("SRV-WSUS", "server", `{"managed_by":"wsus","wsus_server":"http://wsus:8530","updates":[]}`, "")
	put("PC-NEVER", "client", "", "")

	c, _ := e.login(t, admin)
	_, body := get(t, c, e.console.URL+"/patches")
	for _, want := range []string{"PC-BEHIND", "SRV-WSUS", "osservazione", "Mozilla.Firefox", "Patch Tuesday", "senza verifica"} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard lacks %q", want)
		}
	}
	// Counts and the pending reboot lead to the patch list and the restart.
	for _, want := range []string{`href="/agents/` + behind + `#patches"`, `href="/agents/` + behind + `#act-reboot-reboot"`} {
		if !strings.Contains(body, want) {
			t.Errorf("patches page lacks the link %s", want)
		}
	}
	// The same badges in the agent list open the agent's panel.
	if _, list := get(t, c, e.console.URL+"/agents"); !strings.Contains(list, `href="/agents?agent=`+behind+`&amp;tab=patches#patches"`) ||
		!strings.Contains(list, `href="/agents?agent=`+behind+`&amp;tab=commands#act-reboot-reboot"`) {
		t.Errorf("agent list badges do not link to the patches and the restart")
	}
	if strings.Index(body, "PC-BEHIND") > strings.Index(body, "PC-OK") || strings.Index(body, "PC-OK") > strings.Index(body, "PC-NEVER") {
		t.Error("endpoints not ranked from the most behind")
	}
	if !strings.Contains(body, "<td>Mozilla Firefox</td><td><code>Mozilla.Firefox</code></td><td>131.0.2</td><td>2</td>") {
		t.Error("outdated application not aggregated")
	}
	if _, body = get(t, c, e.console.URL+"/patches?family=server"); strings.Contains(body, "PC-BEHIND") || !strings.Contains(body, "SRV-WSUS") {
		t.Error("server filter")
	}
	_, body = get(t, c, e.console.URL+"/agents/"+behind)
	for _, want := range []string{"KB5066835", "riavvio in sospeso", "Google.Chrome", "Windows Update"} {
		if !strings.Contains(body, want) {
			t.Errorf("agent page lacks %q", want)
		}
	}
}
