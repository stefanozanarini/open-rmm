package e2e

import (
	"context"
	"encoding/json"
	"net/url"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/updates"
	"google.golang.org/protobuf/proto"
)

const firmwareReport = `{"vendor":"dell","supported":true,"tool":"Dell Command Update","updates":[
 {"id":"ABC12","title":"Dell BIOS Update","version":"1.21.0","category":"bios","severity":"critical"},
 {"id":"DEF34","title":"Intel Wi-Fi Driver","version":"23.60","category":"driver","severity":"recommended"}],
 "checks":[{"id":"firmware","status":"warning","summary":"2 aggiornamenti firmware/driver, BIOS da aggiornare"}]}`

func TestFirmwareReportIsStored(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("uses the sh entrypoint")
	}
	e := start(t)
	fw := e.publish(t, resultModule(t, "firmware", "1.0.0", "scan", firmwareReport))
	_, agentID := startAgent(t, e, true)
	if j := e.waitFinal(t, e.queue(t, agentID, fw, "scan", "{}")); j.State != store.JobSucceeded {
		t.Fatalf("job: %s %s", j.State, j.Error)
	}
	var list []store.UpdateStatus
	waitFor(t, func() bool {
		list, _ = e.store.ListUpdateStatus(context.Background(), e.tenant, agentID)
		return len(list) == 1
	})
	if st := list[0]; st.Source != updates.SourceFirmware || st.Important != 1 || st.Other != 1 {
		t.Fatalf("firmware status = %+v", st)
	}
}

func TestConsoleFirmwareDashboardAndInstall(t *testing.T) {
	e := startConsole(t)
	ctx := context.Background()
	publishTo(t, e.store, filepath.Join(repoRoot(t), "modules", "firmware"))
	pc := e.addWindowsAgent(t, "PC-DELL")
	rep, _ := updates.ParseFirmware([]byte(firmwareReport), time.Now())
	raw, _ := json.Marshal(rep)
	e.store.PutUpdateStatus(ctx, store.UpdateStatus{TenantID: e.tenant, AgentID: pc, Source: updates.SourceFirmware,
		ScannedAt: rep.ScannedAt, Data: raw, ManagedBy: "none", Important: 1, Other: 1})
	c, csrf := e.login(t, admin)

	_, body := get(t, c, e.console.URL+"/patches")
	if !strings.Contains(body, "con BIOS, firmware o driver da aggiornare") || !strings.Contains(body, "BIOS: 1") {
		t.Fatalf("dashboard: %s", body)
	}
	_, body = get(t, c, e.console.URL+"/agents/"+pc)
	if !strings.Contains(body, "Dell BIOS Update") || !strings.Contains(body, `action="/agents/`+pc+`/firmware"`) {
		t.Fatalf("agent page: %s", body)
	}
	// Drivers only by default; the BIOS needs the explicit choice.
	_, _, final := post(t, c, e.console.URL+"/agents/"+pc+"/firmware", url.Values{"csrf": {csrf}, "types": {"driver", "bogus"}, "severity": {"critical"}})
	if !strings.HasPrefix(final.Path, "/jobs/") {
		t.Fatalf("install: at %s", final)
	}
	j, _ := e.store.GetJob(ctx, e.tenant, strings.TrimPrefix(final.Path, "/jobs/"))
	env := &openrmmv1.SignedEnvelope{}
	proto.Unmarshal(j.Envelope, env)
	job := &openrmmv1.Job{}
	proto.Unmarshal(env.GetPayload(), job)
	if job.GetModule() != "firmware" || job.GetAction() != "install" ||
		string(job.GetParamsJson()) != `{"include_bios":false,"severity":"critical","types":["driver"]}` {
		t.Fatalf("signed job = %s %s %s", job.GetModule(), job.GetAction(), job.GetParamsJson())
	}
	if _, body, _ = post(t, c, e.console.URL+"/agents/"+pc+"/firmware", url.Values{"csrf": {csrf}}); !strings.Contains(body, "Seleziona almeno un tipo") {
		t.Fatal("empty selection accepted")
	}
}
