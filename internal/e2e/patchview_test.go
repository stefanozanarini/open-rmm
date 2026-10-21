package e2e

import (
	"context"
	"fmt"
	"html"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/open-rmm/internal/console/jobreq"
	"github.com/stefanozanarini/open-rmm/internal/console/signer"
	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/console/web"
	"github.com/stefanozanarini/open-rmm/internal/updates"
)

// The patch table: missing and installed updates, search, selection for
// install, and an on-demand scan signed without a new sign-in.
func TestConsolePatchView(t *testing.T) {
	e := startConsole(t, func(cfg *web.Config, _ *signer.Server, _ string) {
		cfg.ModuleBundle = web.ModuleBundle{Dir: filepath.Join("..", "..", "modules")} // params.json of the repository's modules
	})
	ctx := context.Background()
	mod := publishTo(t, e.store, filepath.Join(repoRoot(t), "modules", "winupdate"))
	pc := e.addWindowsAgent(t, "PC-PATCH")
	now := time.Now().UTC()
	raw := []byte(`{"managed_by":"none","scanned_at":"` + now.Format(time.RFC3339) + `",
	  "updates":[{"id":"a","title":"2026-10 Cumulative Update for Windows Server 2019 (KB5066586)","kbs":["KB5066586"],"classification":"security","severity":"Critical"},
	             {"id":"b","title":"Update for Microsoft Defender (KB2267602)","kbs":["KB2267602"],"classification":"definition"}],
	  "pending_reboot":{"required":false},
	  "history":[{"title":"2026-09 Cumulative Update (KB5065428)","kbs":["KB5065428"],"date":"2026-09-20T10:00:00Z","result":"succeeded"},
	             {"title":"Broken update (KB5000001)","kbs":["KB5000001"],"date":"2026-09-10T10:00:00Z","result":"failed"}]}`)
	rep, err := updates.ParseWindows(raw, now)
	if err != nil || len(rep.History) != 2 {
		t.Fatalf("report: %+v %v", rep, err)
	}
	e.store.PutUpdateStatus(ctx, store.UpdateStatus{TenantID: e.tenant, AgentID: pc, Source: updates.SourceWindows, ScannedAt: now, Data: raw})

	c, csrf := e.login(t, admin)
	_, body := get(t, c, e.console.URL+"/agents/"+pc)
	body = html.UnescapeString(body)
	for _, want := range []string{`value="KB5066586" checked`, `value="KB2267602"`, "support.microsoft.com/help/5066586", "KB5065428", "non riuscito",
		`name="p.classifications" value="driver"`, "Cerca aggiornamenti ora"} {
		if !strings.Contains(body, want) {
			t.Fatalf("patch view lacks %q: %s", want, body)
		}
	}
	if strings.Contains(body, `value="KB2267602" checked`) {
		t.Fatal("non-security update preselected")
	}
	if _, body = get(t, c, e.console.URL+"/agents/"+pc+"?pq=defender"); strings.Contains(body, "KB5066586") || !strings.Contains(body, "KB2267602") {
		t.Fatal("search ignored")
	}

	// Past installations: only the 10 most recent, unless searching.
	busy := e.addWindowsAgent(t, "PC-HISTORY")
	var hist []string
	for d := 1; d <= 13; d++ {
		hist = append(hist, fmt.Sprintf(`{"title":"Update %02d (KB50000%02d)","kbs":["KB50000%02d"],"date":"2026-09-%02dT10:00:00Z","result":"succeeded"}`, d, d, d, d))
	}
	e.store.PutUpdateStatus(ctx, store.UpdateStatus{TenantID: e.tenant, AgentID: busy, Source: updates.SourceWindows, ScannedAt: now,
		Data: []byte(`{"managed_by":"none","updates":[],"pending_reboot":{"required":false},"history":[` + strings.Join(hist, ",") + `]}`)})
	_, body = get(t, c, e.console.URL+"/agents/"+busy)
	if !strings.Contains(body, "KB5000013") || !strings.Contains(body, "KB5000004") || strings.Contains(body, "KB5000003") ||
		!strings.Contains(body, "altre 3 più vecchie") || strings.Index(body, "KB5000013") > strings.Index(body, "KB5000012") {
		t.Fatalf("history not limited to the 10 most recent: %s", body)
	}
	if _, body = get(t, c, e.console.URL+"/agents/"+busy+"?pq=KB5000001"); !strings.Contains(body, "Update 01") {
		t.Fatal("older installation not found by search")
	}

	// On-demand scan: signed at once, no step-up.
	e.idp.mu.Lock()
	before := e.idp.lastAuth
	e.idp.mu.Unlock()
	_, body, _ = post(t, c, e.console.URL+"/agents/"+pc+"/collect", url.Values{"csrf": {csrf}, "module": {"winupdate"}, "action": {"scan"}})
	if !strings.Contains(body, "Raccolta avviata") {
		t.Fatalf("collect: %s", body)
	}
	e.idp.mu.Lock()
	after := e.idp.lastAuth
	e.idp.mu.Unlock()
	if after.Encode() != before.Encode() {
		t.Fatal("collection asked for a sign-in")
	}
	jobs, _ := e.store.ListJobs(ctx, e.tenant, pc, 5)
	if len(jobs) != 1 || jobs[0].Module != "winupdate" || jobs[0].Action != "scan" || jobs[0].ModuleVersion != mod.Manifest.Version {
		t.Fatalf("jobs = %+v", jobs)
	}
	// The signer signs only standard collections without an operator.
	for name, req := range map[string]*openrmmv1.JobRequest{
		"install":    {Module: "winupdate", Action: "install"},
		"parameters": {Module: "winupdate", Action: "scan", ParamsJson: []byte(`{"max_age_days":1}`)},
		"script":     {Module: "script", Action: "run"},
	} {
		req.TenantId, req.AgentId, req.ModuleVersion, req.ModuleSha256 = e.tenant, pc, mod.Manifest.Version, mod.ManifestHash
		req.TtlSeconds, req.RequestNonce = 600, jobreq.NewRequestNonce()
		if req.ParamsJson == nil {
			req.ParamsJson = []byte("{}")
		}
		if _, err := e.signer.SignCollect(ctx, &openrmmv1.SignCollectRequest{Request: req}); err == nil {
			t.Errorf("%s signed without an operator", name)
		}
	}
	// Installing the selection carries the chosen KBs and every classification.
	form := url.Values{"csrf": {csrf}, "target": {"winupdate|" + mod.Manifest.Version + "|install"}, "ttl_minutes": {"480"},
		"p.include_kbs": {"KB5066586", "KB2267602"}, "p.classifications": {"security", "definition", "driver"}}
	if code, _, _ := post(t, c, e.console.URL+"/agents/"+pc+"/jobs", form); code != 200 {
		t.Fatalf("install: %d", code)
	}
	jobs, _ = e.store.ListJobs(ctx, e.tenant, pc, 5)
	if len(jobs) != 2 || !strings.Contains(string(jobs[0].Params)+string(jobs[1].Params), `"include_kbs":["KB5066586","KB2267602"]`) {
		t.Fatalf("install params: %s / %s", jobs[0].Params, jobs[1].Params)
	}

	// Without a parameter description, chosen values are refused rather
	// than dropped (the action would run on every update).
	e2 := startConsole(t)
	m2 := publishTo(t, e2.store, filepath.Join(repoRoot(t), "modules", "winupdate"))
	pc2 := e2.addWindowsAgent(t, "PC-NOPARAMS")
	c2, csrf2 := e2.login(t, admin)
	_, body, _ = post(t, c2, e2.console.URL+"/agents/"+pc2+"/jobs", url.Values{"csrf": {csrf2}, "target": {"winupdate|" + m2.Manifest.Version + "|install"},
		"p.include_kbs": {"KB5066586"}})
	if !strings.Contains(html.UnescapeString(body), "non descrive i suoi parametri") {
		t.Fatal("parameters dropped silently")
	}
}
