package e2e

import (
	"context"
	"encoding/json"
	"html"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/open-rmm/internal/console/authn"
	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/ids"
	"github.com/stefanozanarini/open-rmm/internal/inventory"
	"google.golang.org/protobuf/proto"
)

// addAgentAt adds an active Windows agent whose inventory reports ip.
func (e *consoleEnv) addAgentAt(t *testing.T, name, ip string) string {
	t.Helper()
	ctx := context.Background()
	id := e.addWindowsAgent(t, name)
	inv := inventory.Inventory{Schema: 1, CollectedAt: time.Now().UTC()}
	raw, _ := json.Marshal(inv)
	if err := e.store.PutInventory(ctx, store.Inventory{TenantID: e.tenant, AgentID: id, Data: raw,
		Summary: store.InventorySummary{CollectedAt: inv.CollectedAt.Add(time.Second), IPv4: []string{ip}}}, nil); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestConsoleSitesPanelNotesAndTheme(t *testing.T) {
	e := startConsole(t)
	ctx := context.Background()
	bo := e.addAgentAt(t, "PC-BOLOGNA", "192.168.1.20")
	mi := e.addAgentAt(t, "PC-MILANO", "10.20.3.4")
	c, csrf := e.login(t, admin)

	// Sites: invalid subnets are refused, duplicates too.
	if _, body, _ := post(t, c, e.console.URL+"/sites", url.Values{"csrf": {csrf}, "name": {"Bologna"}, "subnets": {"192.168.1.0/33"}}); !strings.Contains(body, "Subnet non valide") {
		t.Fatal("invalid subnet accepted")
	}
	post(t, c, e.console.URL+"/sites", url.Values{"csrf": {csrf}, "name": {"Bologna"}, "subnets": {"192.168.1.0/24"}})
	post(t, c, e.console.URL+"/sites", url.Values{"csrf": {csrf}, "name": {"Milano"}, "subnets": {"10.20.0.0/16\n10.21.0.0/16"}})
	if _, body, _ := post(t, c, e.console.URL+"/sites", url.Values{"csrf": {csrf}, "name": {"Milano"}, "subnets": {"10.30.0.0/16"}}); !strings.Contains(html.UnescapeString(body), "Esiste già una sede") {
		t.Fatal("duplicate site accepted")
	}
	sites, _ := e.store.ListSites(ctx, e.tenant)
	if len(sites) != 2 {
		t.Fatalf("sites = %+v", sites)
	}
	var boID string
	for _, s := range sites {
		if s.Name == "Bologna" {
			boID = s.ID
		}
	}

	// The tree filters the list by site; agents outside every site are under "none".
	_, body := get(t, c, e.console.URL+"/agents?site="+boID)
	if !strings.Contains(body, "PC-BOLOGNA") || strings.Contains(body, "PC-MILANO") {
		t.Fatal("site filter: Bologna")
	}
	_, body = get(t, c, e.console.URL+"/agents?site=none")
	if strings.Contains(body, "PC-BOLOGNA") || strings.Contains(body, "PC-MILANO") {
		t.Fatal("site filter: none")
	}

	// Bottom panel with tabs, and a note added from it.
	_, body = get(t, c, e.console.URL+"/agents?agent="+mi+"&tab=notes")
	if !strings.Contains(body, `class="panel"`) || !strings.Contains(body, "Nuova nota") {
		t.Fatal("notes tab not shown in the panel")
	}
	ret := "/agents?agent=" + mi + "&tab=notes"
	code, body, final := post(t, c, e.console.URL+"/agents/"+mi+"/notes", url.Values{"csrf": {csrf}, "body": {"Disco da sostituire <b>"}, "return": {ret}})
	if code != 200 || final.RequestURI() != ret || !strings.Contains(body, "Disco da sostituire &lt;b&gt;") {
		t.Fatalf("add note: %d at %s", code, final)
	}
	notes, _ := e.store.ListNotes(ctx, e.tenant, mi, 10)
	if len(notes) != 1 || !strings.Contains(notes[0].Author, admin.Username) {
		t.Fatalf("notes = %+v", notes)
	}
	// The return target stays inside the console.
	_, _, final = post(t, c, e.console.URL+"/agents/"+bo+"/notes", url.Values{"csrf": {csrf}, "body": {"x"}, "return": {"https://evil.example/"}})
	if final.Host != strings.TrimPrefix(e.console.URL, "https://") || final.Path != "/agents/"+bo {
		t.Fatalf("note redirect to %s", final)
	}

	// Each tab renders.
	for _, tab := range []string{"summary", "checks", "patches", "software", "inventory", "logons", "policies", "history", "notes", "commands"} {
		if code, _ := get(t, c, e.console.URL+"/agents?agent="+bo+"&tab="+tab); code != 200 {
			t.Errorf("tab %s: %d", tab, code)
		}
	}

	// Theme, kept in the session.
	_, _, final = post(t, c, e.console.URL+"/theme", url.Values{"csrf": {csrf}, "theme": {"dark"}, "return": {"//evil.example/"}})
	if final.Path != "/agents" {
		t.Fatalf("theme redirect to %s", final)
	}
	if _, body = get(t, c, e.console.URL+"/agents"); !strings.Contains(body, `data-theme="dark"`) {
		t.Fatal("dark theme not applied")
	}

	// Only admins manage sites; notes need an operator.
	op := admin
	op.OID, op.Roles = ids.NewUUID(), []string{authn.RoleOperator}
	oc, ocsrf := e.login(t, op)
	if code, _, _ := post(t, oc, e.console.URL+"/sites", url.Values{"csrf": {ocsrf}, "name": {"Roma"}, "subnets": {"10.9.0.0/16"}}); code != http.StatusForbidden {
		t.Fatalf("operator saved a site: %d", code)
	}
	reader := admin
	reader.OID, reader.Roles = ids.NewUUID(), []string{authn.RoleReader}
	rc, rcsrf := e.login(t, reader)
	if code, _, _ := post(t, rc, e.console.URL+"/agents/"+bo+"/notes", url.Values{"csrf": {rcsrf}, "body": {"x"}}); code != http.StatusForbidden {
		t.Fatalf("reader added a note: %d", code)
	}
}

func TestConsoleBulkCommandAndDeploy(t *testing.T) {
	e := startConsole(t)
	ctx := context.Background()
	publishTo(t, e.store, filepath.Join(repoRoot(t), "modules", "script"))
	publishTo(t, e.store, filepath.Join(repoRoot(t), "modules", "software"))
	pc1 := e.addWindowsAgent(t, "PC-01")
	pc2 := e.addWindowsAgent(t, "PC-02")
	c, csrf := e.login(t, admin)

	// The selection from the list opens the bulk page with the actions every
	// selected agent can run.
	_, body := get(t, c, e.console.URL+"/agents/bulk?"+url.Values{"agent": {pc1, pc2}}.Encode())
	if !strings.Contains(body, "Azioni su 2 agenti") || !strings.Contains(body, "script|1.0.0|run") {
		t.Fatalf("bulk page: %s", body)
	}
	// A pending (not approved) agent cannot be part of a selection.
	if _, body = get(t, c, e.console.URL+"/agents/bulk?"+url.Values{"agent": {pc1, e.agentID}}.Encode()); !strings.Contains(body, "Solo gli agenti approvati") {
		t.Fatal("pending agent accepted in a selection")
	}

	// One step-up, one signed job per agent.
	code, body, final := post(t, c, e.console.URL+"/agents/bulk", url.Values{"csrf": {csrf}, "agent": {pc1, pc2},
		"target": {"script|1.0.0|run"}, "script": {"Get-Date"}, "ttl_minutes": {"60"}})
	if code != 200 || final.Path != "/jobs" || !strings.Contains(body, "2 comandi approvati") {
		t.Fatalf("bulk run: %d at %s", code, final)
	}
	jobs, _ := e.store.ListJobs(ctx, e.tenant, "", 10)
	seen := map[string]bool{}
	for _, j := range jobs {
		env := &openrmmv1.SignedEnvelope{}
		proto.Unmarshal(j.Envelope, env)
		job := &openrmmv1.Job{}
		proto.Unmarshal(env.GetPayload(), job)
		if e.jobKeys.Verify("openrmm/job/v1", env.GetKeyId(), env.GetPayload(), env.GetSignature()) != nil ||
			job.GetAgentId() != j.AgentID || job.GetModule() != "script" || !strings.Contains(string(job.GetParamsJson()), "Get-Date") {
			t.Fatalf("signed job = %+v", job)
		}
		seen[j.AgentID] = true
	}
	if len(jobs) != 2 || !seen[pc1] || !seen[pc2] {
		t.Fatalf("jobs for %v", seen)
	}

	// A package goes to the deploy page with the selection preselected.
	sha := strings.Repeat("ab", 32)
	if err := e.store.PutPackage(ctx, store.Package{TenantID: e.tenant, SHA256: sha, Name: "Tool", Version: "1.0",
		FileName: "tool.msi", Size: 10, Kind: "msi", Source: "upload", CreatedBy: "t"}); err != nil {
		t.Fatal(err)
	}
	_, body, final = post(t, c, e.console.URL+"/agents/bulk", url.Values{"csrf": {csrf}, "agent": {pc1, pc2}, "package": {sha}})
	if final.Path != "/packages/"+sha+"/deploy" || strings.Count(body, " checked") != 2 {
		t.Fatalf("deploy from selection: %s", final)
	}
}
