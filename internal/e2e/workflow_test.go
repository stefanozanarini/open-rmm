package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"html"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stefanozanarini/tempra-rmm/internal/console/store"
	"github.com/stefanozanarini/tempra-rmm/internal/workflow"
)

func TestWorkflows(t *testing.T) {
	e := startConsole(t)
	ctx := context.Background()
	publishTo(t, e.store, filepath.Join(repoRoot(t), "modules", "workflow"))
	pc := e.addWindowsAgent(t, "PC-01")
	c, csrf := e.login(t, admin)
	file := []byte("an installer")
	if code, body := upload(t, c, e.console.URL+"/packages/upload", [][2]string{{"csrf", csrf}, {"name", "Setup Tool"},
		{"version", "2.0"}, {"kind", "msi"}}, file); code != 200 {
		t.Fatalf("upload: %d %s", code, body)
	}
	sum := sha256.Sum256(file)
	sha := hex.EncodeToString(sum[:])
	e.store.SetPackageUnsigned(ctx, e.tenant, sha, true)

	// Steps come in the order of their order fields; blank rules are left out.
	form := url.Values{"csrf": {csrf}, "name": {"Setup Tool"}, "comment": {"prima versione"},
		"d.match": {"all"}, "d.r.0.type": {"app"}, "d.r.0.name": {"Setup Tool*"}, "d.r.0.op": {"version_ge"}, "d.r.0.value": {"2.0"},
		"d.r.1.type": {""},
		"s.0.type":   {"script"}, "s.0.order": {"1"}, "s.0.script": {"Stop-Process -Name tool -ErrorAction SilentlyContinue"},
		"s.0.match": {"any"}, "s.0.r.0.type": {"user_group"}, "s.0.r.0.name": {`CORP\Contabilità`}, "s.0.url": {"https://ignored"},
		"s.1.type": {"install"}, "s.1.order": {"0"}, "s.1.package": {sha}, "s.1.args": {"ALLUSERS=1"}, "s.1.timeout": {"10"},
		"s.5.type": {"http"}, "s.5.order": {"2"}, "s.5.method": {"POST"}, "s.5.url": {"https://hooks.example.com/done"},
		"s.5.body": {`{"pc":"%COMPUTERNAME%"}`}, "s.5.continue": {"1"}}
	_, body, at := post(t, c, e.console.URL+"/workflows/new", form)
	if !strings.Contains(body, "Workflow Setup Tool salvato: revisione 1") {
		t.Fatalf("create: %s", body)
	}
	id := strings.TrimPrefix(at.Path, "/workflows/")
	wf, err := e.store.GetWorkflow(ctx, e.tenant, id, 0)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := workflow.Parse(wf.Document)
	if err != nil || len(doc.Steps) != 3 || doc.Steps[0].Type != "install" || doc.Steps[0].TimeoutSeconds != 600 ||
		doc.Steps[1].When.Match != "any" || doc.Steps[1].URL != "" || doc.Steps[2].Method != "POST" || !doc.Steps[2].ContinueOnError ||
		len(doc.Detection.Rules) != 1 || wf.Comment != "prima versione" {
		t.Fatalf("saved workflow = %+v %+v, %v", wf, doc, err)
	}

	// An invalid workflow is shown again with the error, nothing saved.
	bad := url.Values{"csrf": {csrf}, "name": {"Setup Tool"}, "s.0.type": {"http"}, "s.0.url": {"ftp://x"}}
	if code, body, _ := post(t, c, e.console.URL+"/workflows/"+id, bad); code != http.StatusUnprocessableEntity ||
		!strings.Contains(body, "Workflow non valido") || !strings.Contains(body, "ftp://x") {
		t.Fatalf("invalid: %d %s", code, body)
	}
	form.Set("comment", "argomenti nuovi")
	form.Set("s.1.args", "ALLUSERS=1 REBOOT=ReallySuppress")
	if _, body, _ = post(t, c, e.console.URL+"/workflows/"+id, form); !strings.Contains(body, "revisione 2") {
		t.Fatalf("revision 2: %s", body)
	}
	if _, body = get(t, c, e.console.URL+"/workflows/"+id+"?rev=1"); !strings.Contains(html.UnescapeString(body), "Stai guardando la revisione 1") {
		t.Fatalf("old revision: %s", body)
	}

	// Run from the bulk actions: one approval, a signed job with the package.
	_, body = get(t, c, e.console.URL+"/agents/bulk?agent="+pc+"&workflow="+id)
	if !strings.Contains(body, "Esegui un workflow") || !strings.Contains(body, `value="`+id+`" selected`) || strings.Contains(body, "workflow|1.0.0|run") {
		t.Fatalf("bulk: %s", body)
	}
	if _, body, _ = post(t, c, e.console.URL+"/agents/bulk", url.Values{"csrf": {csrf}, "agent": {pc}, "workflow": {id},
		"ttl_minutes": {"1440"}}); !strings.Contains(body, "riquadro in basso a destra") {
		t.Fatalf("run: %s", body)
	}
	// Not as a generic action, which would skip the validation.
	if _, body, _ = post(t, c, e.console.URL+"/agents/bulk", url.Values{"csrf": {csrf}, "agent": {pc}, "target": {"workflow|1.0.0|run"},
		"script": {"x"}}); !strings.Contains(body, "Azione non disponibile") {
		t.Fatalf("generic workflow action: %s", body)
	}
	j := lastJob(t, e.store, e.tenant, pc)
	var p workflow.Params
	if err := json.Unmarshal(j.Params, &p); err != nil || j.Module != "workflow" || j.Action != "run" || len(j.Packages) != 1 ||
		j.Packages[0] != sha || p.WorkflowID != id || p.Revision != 2 || !p.Workflow.Steps[0].AllowUnsigned {
		t.Fatalf("job = %+v, params %+v, %v", j, p, err)
	}
	if _, body = get(t, c, e.console.URL+"/workflows"); !strings.Contains(body, `badge running`) {
		t.Fatalf("running status: %s", body)
	}
	e.store.UpdateJob(ctx, e.tenant, pc, j.ID, store.JobUpdate{State: store.JobSucceeded, Progress: 100,
		Result: []byte(`{"compliant":true,"verified":true,"steps":[]}`)}, time.Now())
	if _, body = get(t, c, e.console.URL+"/workflows/"+id); !strings.Contains(body, "già conforme") || !strings.Contains(body, "PC-01") {
		t.Fatalf("compliant status: %s", body)
	}

	if _, body, _ = post(t, c, e.console.URL+"/workflows/"+id, url.Values{"csrf": {csrf}, "delete": {"1"}}); !strings.Contains(body, "Workflow Setup Tool eliminato") {
		t.Fatalf("delete: %s", body)
	}
}
