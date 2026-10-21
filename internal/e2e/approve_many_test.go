package e2e

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/console/authn"
	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/ids"
)

// Pending agents can be approved, or turned down, several at a time.
func TestApproveSelectedAgents(t *testing.T) {
	e := startConsole(t)
	ctx := context.Background()
	pending := func(name string) string {
		id := ids.NewUUID()
		e.store.CreateAgent(ctx, store.Agent{TenantID: e.tenant, ID: id, Status: store.AgentPending, CertFingerprint: id,
			Host: store.HostInfo{Hostname: name, OS: "windows", OSFamily: "server"}, CertNotAfter: time.Now().Add(time.Hour)})
		return id
	}
	a, b, c3, d := pending("SRV-A"), pending("SRV-B"), pending("SRV-C"), pending("SRV-D")
	c, csrf := e.login(t, admin)
	if _, body := get(t, c, e.console.URL+"/agents"); !strings.Contains(body, `action="/agents/approve"`) || !strings.Contains(body, `value="`+a+`"`) {
		t.Fatal("pending agents cannot be selected")
	}
	_, body, _ := post(t, c, e.console.URL+"/agents/approve", url.Values{"csrf": {csrf}, "do": {"approve"}, "agent": {a, b, "not-a-uuid"}})
	if !strings.Contains(body, "2 agenti approvati.") {
		t.Fatalf("approve: %s", body)
	}
	_, body, _ = post(t, c, e.console.URL+"/agents/approve", url.Values{"csrf": {csrf}, "do": {"revoke"}, "agent": {c3, a}})
	if !strings.Contains(body, "1 agenti rifiutati e revocati.") { // a is no longer pending
		t.Fatalf("reject: %s", body)
	}
	for id, want := range map[string]store.AgentStatus{a: store.AgentActive, b: store.AgentActive, c3: store.AgentRevoked, d: store.AgentPending} {
		if got, _ := e.store.GetAgent(ctx, e.tenant, id); got.Status != want {
			t.Errorf("%s: %s, want %s", got.Host.Hostname, got.Status, want)
		}
	}
	// Operators approve too; readers cannot.
	op := opIdentity{OID: ids.NewUUID(), Name: "Op", Username: "op@cliente.it", Roles: []string{authn.RoleOperator}, AMR: []string{"pwd", "mfa"}}
	oc, ocsrf := e.login(t, op)
	if _, body := get(t, oc, e.console.URL+"/agents"); !strings.Contains(body, `action="/agents/approve"`) {
		t.Fatal("operator cannot select pending agents")
	}
	if _, body, _ := post(t, oc, e.console.URL+"/agents/approve", url.Values{"csrf": {ocsrf}, "do": {"approve"}, "agent": {d}}); !strings.Contains(body, "1 agenti approvati.") {
		t.Fatalf("operator approval: %s", body)
	}
	if code, _, _ := post(t, oc, e.console.URL+"/agents/"+a+"/revoke", url.Values{"csrf": {ocsrf}}); code != 403 {
		t.Errorf("operator revoked an approved agent: %d", code)
	}
	e2 := pending("SRV-E")
	rd := opIdentity{OID: ids.NewUUID(), Name: "Reader", Username: "rd@cliente.it", Roles: []string{authn.RoleReader}, AMR: []string{"pwd", "mfa"}}
	rc, rcsrf := e.login(t, rd)
	if code, _, _ := post(t, rc, e.console.URL+"/agents/approve", url.Values{"csrf": {rcsrf}, "do": {"approve"}, "agent": {e2}}); code != 403 {
		t.Errorf("reader approval: %d", code)
	}
	if got, _ := e.store.GetAgent(ctx, e.tenant, e2); got.Status != store.AgentPending {
		t.Error("reader approved an agent")
	}
}
