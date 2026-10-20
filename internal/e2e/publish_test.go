package e2e

import (
	"archive/zip"
	"bytes"
	"context"
	"html"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"testing"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/open-rmm/internal/console/authn"
	"github.com/stefanozanarini/open-rmm/internal/console/signer"
	"github.com/stefanozanarini/open-rmm/internal/console/web"
	"github.com/stefanozanarini/open-rmm/internal/ids"
	"github.com/stefanozanarini/open-rmm/internal/modules"
	"github.com/stefanozanarini/open-rmm/internal/release"
	"github.com/stefanozanarini/open-rmm/internal/signing"
)

// postMultipart sends a multipart form: fields in order (csrf first, as the
// browser sends it), then files.
func postMultipart(t *testing.T, c *http.Client, u string, fields [][2]string, files map[string][]byte) (int, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for _, f := range fields {
		mw.WriteField(f[0], f[1])
	}
	for name, data := range files {
		w, _ := mw.CreateFormFile(name, name+".bin")
		w.Write(data)
	}
	mw.Close()
	resp, err := c.Post(u, mw.FormDataContentType(), &buf)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, html.UnescapeString(string(b))
}

// moduleZip is a module folder zipped as Explorer does: one top folder.
func moduleZip(t *testing.T, version string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range map[string]string{
		"hello/manifest.json": `{"id": "hello", "version": "` + version + `", "description": "test", "protocol_version": 1,
			"entrypoints": {"windows/amd64": {"type": "powershell", "path": "Main.ps1"}},
			"actions": {"say": {"timeout_seconds": 60}}}`,
		"hello/Main.ps1": "Write-Output hello",
	} {
		w, _ := zw.Create(name)
		io.WriteString(w, body)
	}
	zw.Close()
	return buf.Bytes()
}

func approvePublish(t *testing.T, e *consoleEnv, c *http.Client, csrf, path, kind string) {
	t.Helper()
	code, body, _ := post(t, c, e.console.URL+path, url.Values{"csrf": {csrf}})
	if code != 200 || !strings.Contains(body, "Firma e pubblica") {
		t.Fatalf("approval %s: %d %s", kind, code, body)
	}
	e.idp.mu.Lock()
	auth := e.idp.lastAuth
	e.idp.mu.Unlock()
	if auth.Get("prompt") != "login" || !strings.HasPrefix(auth.Get("nonce"), "publish."+kind+".") {
		t.Fatalf("no step-up: %v", auth)
	}
}

// Module and release keys held by the builder: created from the console,
// put into installers, and used to publish modules and releases after an
// MFA approval and the passphrase.
func TestConsolePublishWithBuilderKeys(t *testing.T) {
	var b *testBuilder
	e := startConsole(t, withBuilder(t, &b), func(cfg *web.Config, _ *signer.Server, _ string) {
		cfg.AgentInstall.ModuleKeys, cfg.AgentInstall.ReleaseKeys = "", ""
	})
	ctx := context.Background()
	c, csrf := e.login(t, admin)

	if _, body := get(t, c, e.console.URL+"/modules"); !strings.Contains(body, "Crea prima le chiavi") {
		t.Fatal("publishing offered without keys")
	}
	_, body := get(t, c, e.console.URL+"/agent-installer")
	if !strings.Contains(body, `action="/agent-installer/signing/keys"`) || !strings.Contains(body, "OPENRMM_MODULE_KEYS") {
		t.Fatalf("installer page: %s", body)
	}
	// One passphrase for every key: the code-signing key exists first.
	if _, err := b.CreateCA(ctx, &openrmmv1.CreateCARequest{Subject: &openrmmv1.CertSubject{Organization: "MSP"}, Passphrase: installerPass}); err != nil {
		t.Fatal(err)
	}
	if _, body, _ = post(t, c, e.console.URL+"/agent-installer/signing/keys", url.Values{"csrf": {csrf}, "passphrase": {"un'altra passphrase lunga"}}); !strings.Contains(html.UnescapeString(body), "wrong passphrase") {
		t.Fatalf("keys with another passphrase: %s", body)
	}
	_, body, _ = post(t, c, e.console.URL+"/agent-installer/signing/keys", url.Values{"csrf": {csrf}, "passphrase": {installerPass}})
	if !strings.Contains(body, "Chiavi di moduli e release create") || strings.Contains(body, "OPENRMM_MODULE_KEYS") {
		t.Fatalf("create keys: %s", body)
	}
	st, _ := b.Status(ctx, nil)
	keys := signing.NewKeyring()
	for k, d := range map[string]signing.Domain{st.GetModuleKey(): signing.DomainModuleManifest, st.GetReleaseKey(): signing.DomainAgentRelease} {
		pub, err := signing.ParsePublicKey(k)
		if err != nil {
			t.Fatal(err)
		}
		keys.Add(pub, d)
	}

	// Module: MFA approval, then the zip with the passphrase.
	approvePublish(t, e, c, csrf, "/modules/publish", "module")
	up := e.console.URL + "/modules/publish/upload"
	fields := [][2]string{{"csrf", csrf}, {"passphrase", "passphrase sbagliata ma lunga"}}
	if _, body := postMultipart(t, c, up, fields, map[string][]byte{"module": moduleZip(t, "1.0.0")}); !strings.Contains(body, "Passphrase errata") {
		t.Fatalf("wrong passphrase: %s", body)
	}
	fields[1][1] = installerPass
	if _, body := postMultipart(t, c, up, fields, map[string][]byte{"module": []byte("not a zip")}); !strings.Contains(body, "zip della cartella") {
		t.Fatalf("not a zip: %s", body)
	}
	if code, _ := postMultipart(t, c, up, [][2]string{{"passphrase", installerPass}, {"csrf", csrf}}, map[string][]byte{"module": moduleZip(t, "1.0.0")}); code != http.StatusForbidden {
		t.Fatalf("csrf not first: %d", code)
	}
	if _, body := postMultipart(t, c, up, fields, map[string][]byte{"module": moduleZip(t, "1.0.0")}); !strings.Contains(body, "Modulo hello 1.0.0 firmato e pubblicato") {
		t.Fatalf("publish module: %s", body)
	}
	mod, err := e.store.GetModule(ctx, "hello", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	bundle := modules.Bundle{KeyID: mod.KeyID, Manifest: mod.Manifest, Signature: mod.Signature, Archive: mod.Archive}
	v, err := bundle.Verify(keys)
	if err != nil || mod.UploadedBy != "operator:"+admin.Username {
		t.Fatalf("published module: %+v, %v", mod.UploadedBy, err)
	}
	if err := modules.Extract(v.Manifest, mod.Archive, t.TempDir()+"/x"); err != nil {
		t.Fatalf("extract: %v", err)
	}
	var sdk bool
	for _, f := range v.Manifest.Files {
		sdk = sdk || f.Path == "_sdk/OpenRmm.psm1"
	}
	if !sdk {
		t.Fatalf("SDK not packed: %+v", v.Manifest.Files)
	}
	// One approval, one publication.
	if _, body := postMultipart(t, c, up, fields, map[string][]byte{"module": moduleZip(t, "1.0.1")}); !strings.Contains(body, "Approvazione scaduta") {
		t.Fatal("approval reused")
	}

	// Release.
	approvePublish(t, e, c, csrf, "/updates/publish", "release")
	rf := [][2]string{{"csrf", csrf}, {"version", "1.2.4"}, {"platform", "windows/amd64"}, {"notes", "test"}, {"passphrase", installerPass}}
	_, body = postMultipart(t, c, e.console.URL+"/updates/publish/upload", rf,
		map[string][]byte{"agent": []byte("MZ agent 1.2.4"), "watchdog": []byte("MZ watchdog 1.2.4")})
	if !strings.Contains(body, "Release 1.2.4 per windows/amd64 firmata e pubblicata") {
		t.Fatalf("publish release: %s", body)
	}
	rel, err := e.store.GetRelease(ctx, "1.2.4", "windows/amd64")
	if err != nil {
		t.Fatal(err)
	}
	m, err := release.Verify(keys, rel.KeyID, rel.Manifest, rel.Signature)
	if err != nil {
		t.Fatal(err)
	}
	agent, _ := e.store.GetReleaseFile(ctx, "1.2.4", "windows/amd64", "openrmm-agent.exe")
	if f, _ := m.File("openrmm-agent.exe"); f.CheckFile(agent) != nil {
		t.Fatal("agent file does not match the signed manifest")
	}

	// Installers trust the builder's keys.
	approve, _, _ := post(t, c, e.console.URL+"/agent-installer/build", url.Values{"csrf": {csrf}, "version": {"1.2.4"}})
	if approve != 200 {
		t.Fatalf("installer approval: %d", approve)
	}
	if _, body, _ = post(t, c, e.console.URL+"/agent-installer/confirm", url.Values{"csrf": {csrf}, "passphrase": {installerPass}}); !strings.Contains(body, "creato e firmato") {
		t.Fatalf("build: %s", body)
	}
	b.mu.Lock()
	p := b.last.GetProperties()
	b.mu.Unlock()
	if p["MODULESIGNINGKEYS"] != st.GetModuleKey() || p["RELEASESIGNINGKEYS"] != st.GetReleaseKey() {
		t.Fatalf("installer keys = %q %q", p["MODULESIGNINGKEYS"], p["RELEASESIGNINGKEYS"])
	}

	events, _ := e.store.ListAudit(ctx, e.tenant)
	var actions []string
	for _, ev := range events {
		actions = append(actions, ev.Action)
	}
	for _, a := range []string{"release_keys.created", "module.published", "release.published"} {
		if !strings.Contains(strings.Join(actions, ","), a) {
			t.Errorf("audit lacks %s: %v", a, actions)
		}
	}

	// Operators cannot publish.
	op := admin
	op.OID, op.Roles = ids.NewUUID(), []string{authn.RoleOperator}
	oc, ocsrf := e.login(t, op)
	if code, _, _ := post(t, oc, e.console.URL+"/modules/publish", url.Values{"csrf": {ocsrf}}); code != http.StatusForbidden {
		t.Fatalf("operator started a publication: %d", code)
	}
	if _, body := get(t, oc, e.console.URL+"/modules"); strings.Contains(body, `action="/modules/publish"`) {
		t.Fatal("publish form shown to an operator")
	}
}
