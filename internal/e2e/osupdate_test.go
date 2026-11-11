package e2e

import (
	"context"
	"html"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/console/signer"
	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/console/web"
	"github.com/stefanozanarini/open-rmm/internal/ids"
	"github.com/stefanozanarini/open-rmm/internal/updates"
)

// A Linux agent: osupdate reports in the winupdate format, shown with the
// package versions, installed by package, all security updates or all.
func TestConsoleLinuxUpdates(t *testing.T) {
	e := startConsole(t, func(cfg *web.Config, _ *signer.Server, _ string) {
		cfg.ModuleBundle = web.ModuleBundle{Dir: filepath.Join("..", "..", "modules")}
	})
	ctx := context.Background()
	mod := publishTo(t, e.store, filepath.Join(repoRoot(t), "modules", "osupdate"))
	pc := ids.NewUUID()
	now := time.Now().UTC()
	e.store.CreateAgent(ctx, store.Agent{TenantID: e.tenant, ID: pc, Status: store.AgentActive, CertFingerprint: pc,
		Host:         store.HostInfo{Hostname: "SRV-UBUNTU", OS: "linux", Arch: "amd64", OSFamily: "server", OSVersion: "Ubuntu 24.04.5 LTS"},
		CertNotAfter: now.Add(time.Hour)})
	raw := []byte(`{"managed_by":"none","manager":"apt","scanned_at":"` + now.Format(time.RFC3339) + `",
	  "updates":[{"id":"openssl","title":"openssl 3.0.13-0ubuntu3.6","classification":"security","severity":"","installed":"3.0.13-0ubuntu3.5","version":"3.0.13-0ubuntu3.6"},
	             {"id":"libaudit1","title":"libaudit1 1:3.1.2-2.1ubuntu0.1","classification":"update","installed":"1:3.1.2-2.1build1.1","version":"1:3.1.2-2.1ubuntu0.1"}],
	  "pending_reboot":{"required":true,"reasons":["packages"]}}`)
	if updates.SourceOf("osupdate", "scan") != updates.SourceWindows {
		t.Fatal("osupdate is not an OS update source")
	}
	rep, err := updates.ParseWindows(raw, now)
	if err != nil || rep.Manager != "apt" || rep.Updates[0].Installed != "3.0.13-0ubuntu3.5" {
		t.Fatalf("report: %+v %v", rep, err)
	}
	e.store.PutUpdateStatus(ctx, store.UpdateStatus{TenantID: e.tenant, AgentID: pc, Source: updates.SourceWindows, ScannedAt: now, Data: raw,
		ManagedBy: "none", Important: 1, Other: 1, Reboot: true})

	c, csrf := e.login(t, admin)
	_, body := get(t, c, e.console.URL+"/agents/"+pc)
	body = html.UnescapeString(body)
	for _, want := range []string{"Aggiornamenti del sistema (apt)", `name="p.packages" value="openssl" checked`, `value="libaudit1"`,
		"3.0.13-0ubuntu3.5 → 3.0.13-0ubuntu3.6", `value="osupdate|` + mod.Manifest.Version + `|install"`, `id="os-security"`,
		`<input type="hidden" name="module" value="osupdate">`} {
		if !strings.Contains(body, want) {
			t.Fatalf("agent page lacks %q: %s", want, body)
		}
	}
	if strings.Contains(body, "Raccogli i log di Windows Update") || strings.Contains(body, "p.classifications") {
		t.Fatal("Windows Update controls on a Linux agent")
	}

	form := url.Values{"csrf": {csrf}, "target": {"osupdate|" + mod.Manifest.Version + "|install"}, "ttl_minutes": {"480"},
		"p.packages": {"openssl"}}
	if code, _, _ := post(t, c, e.console.URL+"/agents/"+pc+"/jobs", form); code != 200 {
		t.Fatalf("install: %d", code)
	}
	form = url.Values{"csrf": {csrf}, "target": {"osupdate|" + mod.Manifest.Version + "|install"}, "ttl_minutes": {"480"},
		"p.security_only": {"true"}}
	if code, _, _ := post(t, c, e.console.URL+"/agents/"+pc+"/jobs", form); code != 200 {
		t.Fatalf("install security: %d", code)
	}
	jobs, _ := e.store.ListJobs(ctx, e.tenant, pc, 5)
	all := ""
	for _, j := range jobs {
		all += string(j.Params) + " "
	}
	if len(jobs) != 2 || !strings.Contains(all, `"packages":["openssl"]`) || !strings.Contains(all, `"security_only":true`) {
		t.Fatalf("install params: %s", all)
	}
	// The jobs list names the computer of each job.
	other := e.addWindowsAgent(t, "PC-ALTRO")
	e.store.CreateJob(ctx, store.Job{TenantID: e.tenant, ID: ids.NewUUID(), AgentID: other, Module: "osupdate", ModuleVersion: mod.Manifest.Version,
		Action: "scan", Envelope: []byte("x"), CreatedBy: "console", ExpiresAt: time.Now().Add(time.Hour)})
	if _, body := get(t, c, e.console.URL+"/jobs"); !strings.Contains(body, `<a href="/jobs?agent=`+pc+`"`) || !strings.Contains(body, "SRV-UBUNTU") ||
		!strings.Contains(body, "PC-ALTRO") {
		t.Fatalf("jobs list without the computer: %s", body)
	}
	if _, body := get(t, c, e.console.URL+"/jobs?agent="+pc); !strings.Contains(body, "Job di SRV-UBUNTU") || strings.Contains(body, "PC-ALTRO") {
		t.Fatalf("jobs of one computer: %s", body)
	}
	if _, body := get(t, c, e.console.URL+"/agents?agent="+pc+"&tab=jobs"); !strings.Contains(body, `href="/jobs?agent=`+pc+`"`) ||
		!strings.Contains(body, "osupdate 1.1.0") || !strings.Contains(body, "Ultimi job") {
		t.Fatalf("jobs tab: %s", body)
	}
	if _, body := get(t, c, e.console.URL+"/jobs?q=altro"); !strings.Contains(body, "PC-ALTRO") || strings.Contains(body, ">SRV-UBUNTU<") {
		t.Fatalf("jobs search: %s", body)
	}

	// The installations are listed on the agent page: Linux has no update
	// history of its own.
	_, body = get(t, c, e.console.URL+"/agents/"+pc)
	body = html.UnescapeString(body)
	for _, want := range []string{"Ultime installazioni", "tutti gli aggiornamenti di sicurezza", "<td>openssl</td>", "Cerca per pacchetto"} {
		if !strings.Contains(body, want) {
			t.Fatalf("agent page lacks %q", want)
		}
	}
	if strings.Contains(body, "Cerca per nome o KB") {
		t.Fatal("Windows search hint on a Linux agent")
	}
}
