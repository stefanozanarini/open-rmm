package e2e

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"html"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/open-rmm/internal/builder"
	"github.com/stefanozanarini/open-rmm/internal/codesign"
	"github.com/stefanozanarini/open-rmm/internal/console/authn"
	"github.com/stefanozanarini/open-rmm/internal/console/signer"
	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/console/web"
	"github.com/stefanozanarini/open-rmm/internal/ids"
	"github.com/stefanozanarini/open-rmm/internal/pki"
)

// testBuilder is the real builder service with Build replaced: the MSI
// tools are tested in internal/builder.
type testBuilder struct {
	*builder.Service
	mu     sync.Mutex
	last   *openrmmv1.BuildRequest
	client openrmmv1.BuilderServiceClient
	ai     web.AgentInstall
}

const fakeMSI = "a signed MSI"

func (b *testBuilder) Build(req *openrmmv1.BuildRequest, stream openrmmv1.BuilderService_BuildServer) error {
	b.mu.Lock()
	b.last = req
	b.mu.Unlock()
	if req.GetPassphrase() != installerPass {
		return status403("wrong passphrase or damaged key")
	}
	sum := sha256.Sum256([]byte(fakeMSI))
	stream.Send(&openrmmv1.BuildChunk{Data: []byte(fakeMSI)})
	return stream.Send(&openrmmv1.BuildChunk{Sha256: hex.EncodeToString(sum[:])})
}

type status403 string

func (e status403) Error() string { return string(e) }

const installerPass = "una passphrase lunga e sicura"

func withBuilder(t *testing.T, b **testBuilder) consoleOpt {
	return func(cfg *web.Config, _ *signer.Server, _ string) {
		dir, _ := os.MkdirTemp("", "bld")
		t.Cleanup(func() { os.RemoveAll(dir) })
		tb := &testBuilder{Service: &builder.Service{Dir: filepath.Join(dir, "state"), Log: slog.New(slog.NewTextHandler(io.Discard, nil))}}
		os.MkdirAll(tb.Dir, 0o700)
		lis, err := net.Listen("unix", filepath.Join(dir, "b.sock"))
		if err != nil {
			t.Fatal(err)
		}
		gs := grpc.NewServer()
		openrmmv1.RegisterBuilderServiceServer(gs, tb)
		go gs.Serve(lis)
		t.Cleanup(gs.Stop)
		conn, _ := grpc.NewClient("unix://"+lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
		t.Cleanup(func() { conn.Close() })
		cfg.Builder = openrmmv1.NewBuilderServiceClient(conn)
		cfg.AgentInstall = web.AgentInstall{Server: "agent.cliente.it:443", RootCA: strings.Repeat("QUJD", 40),
			JobKeys: "ed25519:job", ModuleKeys: "ed25519:mod", ReleaseKeys: "ed25519:rel"}
		tb.client, tb.ai = cfg.Builder, cfg.AgentInstall
		*b = tb
	}
}

func TestConsoleInstallerWithDedicatedCA(t *testing.T) {
	var b *testBuilder
	e := startConsole(t, withBuilder(t, &b))
	ctx := context.Background()
	e.store.PutRelease(ctx, store.Release{Version: "1.2.3", Platform: "windows/amd64",
		Files: map[string][]byte{"openrmm-agent.exe": []byte("MZ agent"), "openrmm-watchdog.exe": []byte("MZ watchdog")}})
	c, csrf := e.login(t, admin)

	_, body := get(t, c, e.console.URL+"/agent-installer")
	if !strings.Contains(body, "Nessun certificato di firma") {
		t.Fatalf("installer page: %s", body)
	}
	ca := url.Values{"csrf": {csrf}, "o": {"Cliente Srl"}, "ou": {"IT"}, "l": {"Bologna"}, "st": {"BO"}, "c": {"it"},
		"passphrase": {installerPass}, "passphrase2": {installerPass + "x"}}
	if _, body, _ = post(t, c, e.console.URL+"/agent-installer/signing/ca", ca); !strings.Contains(body, "non coincidono") {
		t.Fatal("mismatched passphrases accepted")
	}
	ca.Set("passphrase2", installerPass)
	_, body, _ = post(t, c, e.console.URL+"/agent-installer/signing/ca", ca)
	if !strings.Contains(body, "CA dedicata e certificato di firma creati") || !strings.Contains(body, "L=Bologna") {
		t.Fatalf("create CA: %s", body)
	}
	if code, cer := get(t, c, e.console.URL+"/setup/codesign-ca.cer"); code != 200 || len(cer) < 100 {
		t.Fatalf("CA certificate not offered for Group Policy: %d", code)
	}

	// Build: MFA approval first, then the passphrase.
	code, body, final := post(t, c, e.console.URL+"/agent-installer/build", url.Values{"csrf": {csrf}, "version": {"1.2.3"}})
	if code != 200 || !strings.Contains(html.UnescapeString(body), "Creazione dell'installer 1.2.3 approvata") {
		t.Fatalf("approval: %d at %s", code, final)
	}
	e.idp.mu.Lock()
	auth := e.idp.lastAuth
	e.idp.mu.Unlock()
	if auth.Get("prompt") != "login" || !strings.HasPrefix(auth.Get("nonce"), "installer.") {
		t.Fatalf("no step-up: %v", auth)
	}
	_, body, _ = post(t, c, e.console.URL+"/agent-installer/confirm", url.Values{"csrf": {csrf}, "passphrase": {installerPass}})
	if !strings.Contains(body, "Installer 1.2.3 creato e firmato") {
		t.Fatalf("build: %s", body)
	}
	b.mu.Lock()
	req := b.last
	b.mu.Unlock()
	p := req.GetProperties()
	if p["SERVER"] != "agent.cliente.it:443" || p["JOBSIGNINGKEYS"] != "ed25519:job" || string(req.GetAgentExe()) != "MZ agent" || len(p["ENROLLTOKEN"]) < 40 {
		t.Fatalf("build request = %v", p)
	}
	// The token in the MSI never approves agents by itself.
	tok, err := e.store.ConsumeEnrollmentToken(ctx, store.HashToken(p["ENROLLTOKEN"]), e.now())
	if err != nil || tok.AutoApprove || tok.TenantID != e.tenant {
		t.Fatalf("installer token = %+v, %v", tok, err)
	}
	list, _ := e.store.ListInstallers(ctx, e.tenant)
	if len(list) != 1 {
		t.Fatalf("installers = %+v", list)
	}
	// One approval, one build.
	if _, body, _ = post(t, c, e.console.URL+"/agent-installer/confirm", url.Values{"csrf": {csrf}, "passphrase": {installerPass}}); !strings.Contains(body, "Approvazione scaduta") {
		t.Fatal("approval reused")
	}

	// Operators download, but cannot build.
	op := admin
	op.OID, op.Roles = ids.NewUUID(), []string{authn.RoleOperator}
	oc, ocsrf := e.login(t, op)
	if code, body := get(t, oc, e.console.URL+"/agent-installer/"+list[0].ID+"/msi"); code != 200 || body != fakeMSI {
		t.Fatalf("download: %d %q", code, body)
	}
	if code, _, _ := post(t, oc, e.console.URL+"/agent-installer/build", url.Values{"csrf": {ocsrf}, "version": {"1.2.3"}}); code != http.StatusForbidden {
		t.Fatalf("operator started a build: %d", code)
	}
	events, _ := e.store.ListAudit(ctx, e.tenant)
	var actions []string
	for _, ev := range events {
		actions = append(actions, ev.Action)
	}
	if all := strings.Join(actions, ","); !strings.Contains(all, "codesign.ca_created") || !strings.Contains(all, "installer.built") {
		t.Fatalf("audit = %s", all)
	}
}

func TestConsoleSigningRequestFlow(t *testing.T) {
	var b *testBuilder
	e := startConsole(t, withBuilder(t, &b))
	c, csrf := e.login(t, admin)
	_, body, _ := post(t, c, e.console.URL+"/agent-installer/signing/request", url.Values{"csrf": {csrf}, "o": {"Cliente Srl"},
		"passphrase": {installerPass}, "passphrase2": {installerPass}})
	if !strings.Contains(body, "Richiesta creata") || !strings.Contains(body, "BEGIN CERTIFICATE REQUEST") {
		t.Fatalf("request: %s", body)
	}
	if code, csr := get(t, c, e.console.URL+"/agent-installer/signing/request.csr"); code != 200 || !strings.Contains(csr, "CERTIFICATE REQUEST") {
		t.Fatalf("csr download: %d", code)
	}
	// A certificate that is not for this request is refused.
	other, _ := codesign.NewCA(codesign.Subject{Organization: "X"}, e.now())
	leaf, _ := other.Issue(codesign.Subject{Organization: "X"}, e.now())
	_, body, _ = post(t, c, e.console.URL+"/agent-installer/signing/certificate", url.Values{"csrf": {csrf},
		"certificate": {string(pemCerts(leaf.Cert, other.Cert))}})
	if !strings.Contains(html.UnescapeString(body), "not issued for the pending request") {
		t.Fatalf("foreign certificate: %s", body)
	}
}

func pemCerts(certs ...*x509.Certificate) []byte { return pki.EncodeCertPEM(certs...) }

func (e *consoleEnv) now() time.Time { return time.Now() }

// The signing key signs every tenant's installers: only Admins of the
// console's own directory manage it, and every tenant sees it.
func TestConsoleWideSigning(t *testing.T) {
	var b *testBuilder
	other := ids.NewUUID() // a customer's directory on the same console
	otherTenant := ids.NewUUID()
	e := startConsole(t, withBuilder(t, &b), func(cfg *web.Config, _ *signer.Server, _ string) {
		cfg.ConsoleAdminDirs = []string{other}
	})
	e.store.CreateTenant(context.Background(), store.Tenant{ID: otherTenant, Name: "Altro"})
	// The test directory's Admin is a tenant Admin, not a console Admin.
	c, csrf := e.login(t, admin)
	if code, _, _ := post(t, c, e.console.URL+"/agent-installer/signing/ca", url.Values{"csrf": {csrf}, "o": {"X"},
		"passphrase": {installerPass}, "passphrase2": {installerPass}}); code != http.StatusForbidden {
		t.Fatalf("tenant Admin changed the console signing key: %d", code)
	}
	if _, body := get(t, c, e.console.URL+"/agent-installer"); strings.Contains(body, `action="/agent-installer/signing/ca"`) ||
		!strings.Contains(body, "lo gestiscono gli amministratori della console") {
		t.Fatal("signing forms shown to a tenant Admin")
	}
	// Created by the console Admin (here directly on the builder), the
	// certificate is visible from every tenant.
	if _, err := b.CreateCA(context.Background(), &openrmmv1.CreateCARequest{Subject: &openrmmv1.CertSubject{Organization: "MSP Srl"}, Passphrase: installerPass}); err != nil {
		t.Fatal(err)
	}
	if code, cer := get(t, c, e.console.URL+"/setup/codesign.cer"); code != 200 || len(cer) < 100 {
		t.Fatalf("certificate download: %d", code)
	}
	if _, body := get(t, c, e.console.URL+"/setup"); !strings.Contains(body, "MSP Srl") {
		t.Fatal("console certificate not shown on the setup page")
	}
}
