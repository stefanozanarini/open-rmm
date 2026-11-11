package e2e

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stefanozanarini/tempra-rmm/internal/console/store"
	"github.com/stefanozanarini/tempra-rmm/internal/ids"
	"github.com/stefanozanarini/tempra-rmm/internal/policy"
)

// A policy using an older version of a published module is flagged.
func TestConsoleStalePolicy(t *testing.T) {
	e := startConsole(t)
	ctx := context.Background()
	publishTo(t, e.store, filepath.Join(repoRoot(t), "modules", "firmware"))
	c, _ := e.login(t, admin)
	id := ids.NewUUID()
	doc, _ := json.Marshal(policy.Policy{ID: id, TenantID: e.tenant, Name: "Install-vendor-tools", Version: 1, AppliesTo: "all",
		Rules: []policy.Rule{{ID: "firmware-install-tool", Module: "firmware", ModuleVersion: "1.2.0", ModuleSHA256: strings.Repeat("ab", 32),
			Action: "install-tool", EverySeconds: 604800}}})
	if err := e.store.AddPolicyVersion(ctx, store.PolicyVersion{TenantID: e.tenant, ID: id, Version: 1, Name: "Install-vendor-tools",
		AppliesTo: "all", Document: doc, CreatedBy: "operator:" + admin.Username}); err != nil {
		t.Fatal(err)
	}
	_, body := get(t, c, e.console.URL+"/policies")
	if !strings.Contains(body, "1 policy usano una versione precedente") || !strings.Contains(body, "firmware: disponibile la") ||
		!strings.Contains(body, `href="/policies/`+id+`">↑`) {
		t.Fatalf("stale policy not flagged: %s", body)
	}
}
