package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/ids"
	"github.com/stefanozanarini/open-rmm/internal/inventory"
)

// fakeWinget serves the manifests of 7zip.7zip 24.08 and its installer.
func fakeWinget(t *testing.T, installer []byte) *httptest.Server {
	sum := sha256.Sum256(installer)
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := "/microsoft/winget-pkgs/master/manifests/7/7zip/7zip/24.08/"
		switch r.URL.Path {
		case "/repos/microsoft/winget-pkgs/contents/manifests/7/7zip/7zip":
			w.Write([]byte(`[{"name":"23.01","type":"dir"},{"name":"24.08","type":"dir"}]`))
		case base + "7zip.7zip.installer.yaml":
			w.Write([]byte("PackageIdentifier: 7zip.7zip\nPackageVersion: \"24.08\"\nInstallers:\n- Architecture: x64\n  InstallerType: msi\n  Scope: machine\n" +
				"  InstallerUrl: " + srv.URL + "/dl/7z2408-x64.msi\n  InstallerSha256: " + hex.EncodeToString(sum[:]) + "\n" +
				"  AppsAndFeaturesEntries:\n  - DisplayName: 7-Zip 24.08 (x64 edition)\n    DisplayVersion: \"24.08.00.0\"\n"))
		case base + "7zip.7zip.yaml":
			w.Write([]byte("DefaultLocale: en-US\n"))
		case base + "7zip.7zip.locale.en-US.yaml":
			w.Write([]byte("Publisher: Igor Pavlov\nPackageName: 7-Zip\n"))
		case "/dl/7z2408-x64.msi":
			w.Write(installer)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func (e *consoleEnv) addWindowsAgent(t *testing.T, name string, software ...inventory.Software) string {
	ctx := context.Background()
	id := ids.NewUUID()
	now := time.Now()
	e.store.CreateAgent(ctx, store.Agent{TenantID: e.tenant, ID: id, Status: store.AgentActive, CertFingerprint: id,
		Host: store.HostInfo{Hostname: name, OS: "windows", Arch: "amd64", OSFamily: "client"}, CertNotAfter: now.Add(time.Hour)})
	inv := inventory.Inventory{Schema: 1, CollectedAt: now.UTC(), Software: software}
	raw, _ := json.Marshal(inv)
	e.store.PutInventory(ctx, store.Inventory{TenantID: e.tenant, AgentID: id, Data: raw,
		Summary: store.InventorySummary{CollectedAt: inv.CollectedAt}}, nil)
	return id
}

func upload(t *testing.T, c *http.Client, u string, fields [][2]string, file []byte) (int, string) {
	t.Helper()
	var b bytes.Buffer
	mw := multipart.NewWriter(&b)
	for _, f := range fields {
		mw.WriteField(f[0], f[1])
	}
	fw, _ := mw.CreateFormFile("file", "Setup Tool 2.0.msi")
	fw.Write(file)
	mw.Close()
	resp, err := c.Post(u, mw.FormDataContentType(), &b)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out bytes.Buffer
	out.ReadFrom(resp.Body)
	return resp.StatusCode, out.String()
}

func TestConsoleCatalogDeployAndUninstall(t *testing.T) {
	e := startConsole(t)
	ctx := context.Background()
	publishTo(t, e.store, filepath.Join(repoRoot(t), "modules", "software"))
	old := inventory.Software{Name: "7-Zip 23.01 (x64)", Version: "23.01", Scope: "machine"}
	pc1 := e.addWindowsAgent(t, "PC-01", old)
	pc2 := e.addWindowsAgent(t, "PC-02", old, inventory.Software{Name: "Notepad++ (64-bit x64)", Version: "8.6", Scope: "machine"})
	e.addWindowsAgent(t, "PC-03", inventory.Software{Name: "7-Zip 24.08 (x64)", Version: "24.08", Scope: "machine"})

	c, csrf := e.login(t, admin)
	_, body, _ := post(t, c, e.console.URL+"/catalog", url.Values{"csrf": {csrf}, "winget_id": {"7zip.7zip"}})
	// Adding an application downloads its installer at once.
	if !strings.Contains(body, "7-Zip 24.08 aggiunto alla libreria") {
		t.Fatalf("add to catalog: %s", body)
	}
	if !strings.Contains(body, `chk-warning">2<`) {
		t.Fatal("two outdated endpoints expected")
	}
	_, body, _ = post(t, c, e.console.URL+"/catalog/7zip.7zip/import", url.Values{"csrf": {csrf}})
	if !strings.Contains(body, "già nella libreria") {
		t.Fatalf("import again: %s", body)
	}
	sum := sha256.Sum256(e.installer)
	sha := hex.EncodeToString(sum[:])
	p, err := e.store.GetPackage(ctx, e.tenant, sha)
	if err != nil || p.Source != "winget" || p.Kind != "msi" || p.FileName != "7z2408-x64.msi" || p.Version != "24.08" {
		t.Fatalf("package = %+v, %v", p, err)
	}
	if f, err := e.packages.Open(sha); err != nil {
		t.Fatal(err)
	} else {
		f.Close()
	}
	// The agent page marks the outdated application.
	if _, body = get(t, c, e.console.URL+"/agents/"+pc1); !strings.Contains(body, "→ 24.08") {
		t.Error("agent page does not mark 7-Zip as outdated")
	}

	// Deploy to the two outdated endpoints with one approval.
	_, body = get(t, c, e.console.URL+"/packages/"+sha+"/deploy")
	if strings.Count(body, "checked") != 2 {
		t.Fatalf("outdated endpoints not preselected: %s", body)
	}
	_, body, _ = post(t, c, e.console.URL+"/packages/"+sha+"/deploy", url.Values{"csrf": {csrf}, "agent": {pc1, pc2}, "ttl_minutes": {"60"}})
	if !strings.Contains(body, "2 comandi approvati") {
		t.Fatalf("deploy: %s", body)
	}
	jobs, _ := e.store.ListJobs(ctx, e.tenant, "", 10)
	targets := map[string]bool{}
	for _, j := range jobs {
		if j.Module != "software" || j.Action != "install" || len(j.Packages) != 1 || j.Packages[0] != sha {
			t.Fatalf("job = %+v", j)
		}
		env := &openrmmv1.SignedEnvelope{}
		proto.Unmarshal(j.Envelope, env)
		job := &openrmmv1.Job{}
		proto.Unmarshal(env.GetPayload(), job)
		if e.jobKeys.Verify("openrmm/job/v1", env.GetKeyId(), env.GetPayload(), env.GetSignature()) != nil ||
			job.GetAgentId() != j.AgentID || len(job.GetPackages()) != 1 || job.GetPackages()[0].GetFileName() != "7z2408-x64.msi" ||
			job.GetPackages()[0].GetSize() != int64(len(e.installer)) {
			t.Fatalf("signed job = %+v", job)
		}
		targets[j.AgentID] = true
	}
	if len(jobs) != 2 || !targets[pc1] || !targets[pc2] {
		t.Fatalf("jobs for %v", targets)
	}

	// Uninstall from the software list of an endpoint.
	_, body, u := post(t, c, e.console.URL+"/agents/"+pc2+"/uninstall", url.Values{"csrf": {csrf}, "name": {"Notepad++ (64-bit x64)"}, "version": {"8.6"}})
	if !strings.HasPrefix(u.Path, "/jobs/") {
		t.Fatalf("uninstall: %s %s", u, body)
	}
	j, _ := e.store.GetJob(ctx, e.tenant, strings.TrimPrefix(u.Path, "/jobs/"))
	if j.Action != "uninstall" || !strings.Contains(string(j.Params), `"name":"Notepad++ (64-bit x64)"`) {
		t.Fatalf("uninstall job = %+v", j)
	}
	if _, body, _ = post(t, c, e.console.URL+"/agents/"+pc2+"/uninstall", url.Values{"csrf": {csrf}, "name": {"open-rmm agent"}}); !strings.Contains(body, "non si disinstalla") {
		t.Fatal("agent uninstall not refused")
	}
}

func TestConsoleUpload(t *testing.T) {
	e := startConsole(t)
	c, csrf := e.login(t, admin)
	file := []byte("an installer")
	fields := [][2]string{{"csrf", csrf}, {"name", "Setup Tool"}, {"version", "2.0"}, {"kind", "msi"}}
	if code, body := upload(t, c, e.console.URL+"/packages/upload", fields, file); code != 200 || !strings.Contains(body, "Setup Tool 2.0 aggiunto") {
		t.Fatalf("upload: %d %s", code, body)
	}
	sum := sha256.Sum256(file)
	if p, err := e.store.GetPackage(context.Background(), e.tenant, hex.EncodeToString(sum[:])); err != nil || p.FileName != "Setup Tool 2.0.msi" || p.Source != "upload" {
		t.Fatalf("package = %+v %v", p, err)
	}
	// The token must come first, and must be valid.
	if code, _ := upload(t, c, e.console.URL+"/packages/upload", [][2]string{{"name", "x"}, {"csrf", csrf}}, file); code != 403 {
		t.Fatalf("token after other fields: %d", code)
	}
	if code, _ := upload(t, c, e.console.URL+"/packages/upload", [][2]string{{"csrf", "wrong"}}, file); code != 403 {
		t.Fatalf("wrong token: %d", code)
	}
	// Other routes do not accept multipart without a token.
	if code, _ := upload(t, c, e.console.URL+"/settings", [][2]string{{"rdp_subnets", "0.0.0.0/0"}}, file); code != 403 {
		t.Fatalf("multipart CSRF bypass on another route: %d", code)
	}
	// Operators cannot upload.
	op := admin
	op.OID, op.Roles = ids.NewUUID(), []string{"OpenRMM.Operator"}
	oc, ocsrf := e.login(t, op)
	if code, _ := upload(t, oc, e.console.URL+"/packages/upload", [][2]string{{"csrf", ocsrf}, {"name", "x"}, {"version", "1"}}, file); code != 403 {
		t.Fatalf("operator upload: %d", code)
	}
}
