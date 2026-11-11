package e2e

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stefanozanarini/tempra-rmm/internal/console/store"
	"github.com/stefanozanarini/tempra-rmm/internal/ids"
)

// The job dock lists the operator's running jobs.
func TestConsoleJobDock(t *testing.T) {
	e := startConsole(t)
	ctx := context.Background()
	publishTo(t, e.store, filepath.Join(repoRoot(t), "modules", "sysinfo"))
	c, _ := e.login(t, admin)
	pc := e.addWindowsAgent(t, "PC-DOCK")
	j := ids.NewUUID()
	if err := e.store.CreateJob(ctx, store.Job{TenantID: e.tenant, ID: j, AgentID: pc, Module: "sysinfo", ModuleVersion: "1.0.0",
		Action: "info", Params: []byte("{}"), Envelope: []byte("x"), CreatedBy: "operator:" + admin.Username,
		ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	// The page must let app.js fetch it (a missing connect-src blocks it).
	resp, err := c.Get(e.console.URL + "/agents")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "connect-src 'self'") {
		t.Fatalf("CSP without connect-src 'self': %s", csp)
	}
	if _, body := get(t, c, e.console.URL+"/jobs/active.json"); !strings.Contains(body, j) || !strings.Contains(body, "PC-DOCK") {
		t.Fatalf("dock: %s", body)
	}
}
