package e2e

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"html"
	"net/http"
	"net/url"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/adinv"
	"github.com/stefanozanarini/open-rmm/internal/codesign"
	"github.com/stefanozanarini/open-rmm/internal/console/authn"
	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/ids"
	"github.com/stefanozanarini/open-rmm/internal/pki"
)

func TestADReportFromAgent(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("uses the sh entrypoint")
	}
	e := start(t)
	m := strings.NewReplacer("ID", adinv.ModuleID, "VERSION", "1.0.0", "PLATFORM", platform()).Replace(fakeInventoryManifest)
	v := e.publish(t, shModule(t, m, `. "$OPENRMM_MODULE_DIR/_sdk/openrmm.sh"; rmm_read_request
rmm_result "{\"schema\":1,\"domain\":\"corp.local\",\"collected_at\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"computers\":[{\"name\":\"PC-01$\",\"dn\":\"CN=PC-01,OU=Bologna,DC=corp,DC=local\",\"enabled\":true}]}"`))
	_, agentID := startAgent(t, e, true)
	if j := e.waitFinal(t, e.queue(t, agentID, v, adinv.Action, "{}")); j.State != store.JobSucceeded {
		t.Fatalf("collect: %s %s", j.State, j.Error)
	}
	var doms []store.ADDomain
	waitFor(t, func() bool { doms, _ = e.store.ListADDomains(context.Background(), e.tenant); return len(doms) == 1 })
	s, err := adinv.Parse(doms[0].Data)
	if err != nil || doms[0].AgentID != agentID || s.Domain != "corp.local" || len(s.Computers) != 1 || s.Computers[0].Name != "PC-01" {
		t.Fatalf("stored = %+v, %v", s, err)
	}
}

func TestConsoleADPageAndOUTree(t *testing.T) {
	e := startConsole(t)
	ctx := context.Background()
	srv := e.addWindowsAgent(t, "SRV-DC01")
	pc := e.addWindowsAgent(t, "PC-01")
	e.addWindowsAgent(t, "WORKGROUP-PC")
	now := time.Now().UTC()
	recent, old := now.Add(-24*time.Hour), now.Add(-200*24*time.Hour)
	snap := adinv.Snapshot{Schema: 1, Domain: "corp.local", CollectedAt: now, Computers: []adinv.Computer{
		{Name: "SRV-DC01", DN: "CN=SRV-DC01,OU=Domain Controllers,DC=corp,DC=local", Enabled: true, LastLogon: &recent},
		{Name: "PC-01", DN: "CN=PC-01,OU=PC,OU=Bologna,DC=corp,DC=local", Enabled: true, LastLogon: &recent},
		{Name: "PC-NOAGENT", DN: "CN=PC-NOAGENT,OU=PC,OU=Bologna,DC=corp,DC=local", Enabled: true, LastLogon: &recent},
		{Name: "PC-OLD", DN: "CN=PC-OLD,CN=Computers,DC=corp,DC=local", Enabled: true, LastLogon: &old},
	}}
	raw, _ := json.Marshal(snap)
	if err := e.store.PutADDomain(ctx, store.ADDomain{TenantID: e.tenant, Domain: "corp.local", AgentID: srv, CollectedAt: now, Data: raw}); err != nil {
		t.Fatal(err)
	}
	c, _ := e.login(t, admin)
	_, body := get(t, c, e.console.URL+"/ad")
	for _, want := range []string{"PC-NOAGENT", "PC-OLD", "200 giorni", "WORKGROUP-PC", "SRV-DC01"} {
		if !strings.Contains(body, want) {
			t.Errorf("AD page lacks %s", want)
		}
	}
	// The OU tree filters the list, sub-OUs included.
	_, body = get(t, c, e.console.URL+"/agents")
	if !strings.Contains(body, ">Bologna <span") || !strings.Contains(body, ">Domain Controllers <span") {
		t.Fatalf("OU tree missing: %s", body)
	}
	_, body = get(t, c, e.console.URL+"/agents?"+url.Values{"ou": {"corp.local/Bologna"}}.Encode())
	if !strings.Contains(body, "PC-01") || strings.Contains(body, "SRV-DC01") || strings.Contains(body, "WORKGROUP-PC") {
		t.Fatal("OU filter")
	}
	// The panel shows where the agent is in the directory.
	if _, body = get(t, c, e.console.URL+"/agents?agent="+pc); !strings.Contains(body, "Bologna/PC") {
		t.Fatal("OU not shown for the agent")
	}
}

func TestConsoleSetupAndCodeSigning(t *testing.T) {
	e := startConsole(t)
	publishTo(t, e.store, filepath.Join(repoRoot(t), "modules", "inventory"))
	publishTo(t, e.store, filepath.Join(repoRoot(t), "modules", "accesslog"))
	c, csrf := e.login(t, admin)

	_, body := get(t, c, e.console.URL+"/setup")
	if !strings.Contains(body, "Configurazione") || !strings.Contains(body, "winupdate") || !strings.Contains(body, "la raccolta di inventario") {
		t.Fatalf("setup page: %s", body)
	}
	// Once synced, the automatic collection is reported as running.
	if err := e.web.SyncBaselines(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, body = get(t, c, e.console.URL+"/setup"); !strings.Contains(body, "vengono raccolti da soli") {
		t.Fatalf("setup page after sync: %s", body)
	}
	// The baseline policy is prefilled with the published modules only.
	_, body = get(t, c, e.console.URL+"/policies/new?template=baseline")
	body = html.UnescapeString(body)
	if !strings.Contains(body, `"module": "inventory"`) || !strings.Contains(body, `"module": "accesslog"`) || strings.Contains(body, `"module": "winupdate"`) {
		t.Fatalf("baseline policy: %s", body)
	}

	now := time.Now()
	s := codesign.Subject{Organization: "Cliente Srl"}
	ca, _ := codesign.NewCA(s, now)
	leaf, _ := ca.Issue(s, now)
	chain := string(pki.EncodeCertPEM(leaf.Cert, ca.Cert))
	key, _ := pki.EncodeKeyPEM(leaf.Key)

	// Keys and CA certificates are refused.
	_, body, _ = post(t, c, e.console.URL+"/setup/codesign", url.Values{"csrf": {csrf}, "certificate": {chain + string(key)}})
	if !strings.Contains(html.UnescapeString(body), "chiave privata") {
		t.Fatal("private key accepted")
	}
	_, body, _ = post(t, c, e.console.URL+"/setup/codesign", url.Values{"csrf": {csrf}, "certificate": {string(pki.EncodeCertPEM(ca.Cert))}})
	if !strings.Contains(body, "Certificato non valido") {
		t.Fatal("CA accepted as signing certificate")
	}
	set, _ := e.store.GetSettings(context.Background(), e.tenant)
	if set.CodeSigningCert != "" {
		t.Fatal("refused certificate stored")
	}

	_, body, _ = post(t, c, e.console.URL+"/setup/codesign", url.Values{"csrf": {csrf}, "certificate": {chain}})
	if !strings.Contains(body, "Certificato di firma aggiornato") || !strings.Contains(body, leaf.Cert.Subject.String()) {
		t.Fatalf("save certificate: %s", body)
	}
	for name, want := range map[string]*x509.Certificate{"codesign.cer": leaf.Cert, "codesign-ca.cer": ca.Cert} {
		resp, err := c.Get(e.console.URL + "/setup/" + name)
		if err != nil {
			t.Fatal(err)
		}
		var b strings.Builder
		buf := make([]byte, 4096)
		for {
			n, err := resp.Body.Read(buf)
			b.Write(buf[:n])
			if err != nil {
				break
			}
		}
		resp.Body.Close()
		if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/pkix-cert" || b.String() != string(want.Raw) {
			t.Fatalf("%s: %d %s", name, resp.StatusCode, resp.Header.Get("Content-Type"))
		}
	}
	if code, _ := get(t, c, e.console.URL+"/setup/other.cer"); code != http.StatusNotFound {
		t.Fatalf("unknown file: %d", code)
	}
	events, _ := e.store.ListAudit(context.Background(), e.tenant)
	if last := events[len(events)-1]; last.Action != "settings.code_signing" {
		t.Fatalf("audit = %s", last.Action)
	}

	// Operators do not see the setup page nor change the certificate.
	op := admin
	op.OID, op.Roles = ids.NewUUID(), []string{authn.RoleOperator}
	oc, ocsrf := e.login(t, op)
	if code, _ := get(t, oc, e.console.URL+"/setup"); code != http.StatusForbidden {
		t.Fatalf("operator opened setup: %d", code)
	}
	if code, _, _ := post(t, oc, e.console.URL+"/setup/codesign", url.Values{"csrf": {ocsrf}, "remove": {"1"}}); code != http.StatusForbidden {
		t.Fatalf("operator removed the certificate: %d", code)
	}
}
