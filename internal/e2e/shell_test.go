package e2e

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/websocket"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/open-rmm/internal/console/authn"
	"github.com/stefanozanarini/open-rmm/internal/console/signer"
	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/console/web"
	"github.com/stefanozanarini/open-rmm/internal/federation"
	"github.com/stefanozanarini/open-rmm/internal/ids"
)

// broker serves the gateway's shell sessions on a Unix socket, as the core.
func (e *env) broker(t *testing.T) openrmmv1.ShellBrokerServiceClient {
	t.Helper()
	dir, _ := os.MkdirTemp("", "sh")
	t.Cleanup(func() { os.RemoveAll(dir) })
	lis, err := net.Listen("unix", filepath.Join(dir, "shell.sock"))
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer()
	openrmmv1.RegisterShellBrokerServiceServer(gs, e.gw.Broker())
	go gs.Serve(lis)
	t.Cleanup(gs.Stop)
	conn, err := grpc.NewClient("unix://"+lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return openrmmv1.NewShellBrokerServiceClient(conn)
}

// shellAgent starts an agent whose local policy allows shells (or not).
func shellAgent(t *testing.T, e *env, allow bool) string {
	cfg := e.agentConfig(t, e.tokenWith(t, 1, true))
	cfg.AllowInteractiveShell = allow
	runAgent(t, cfg)
	return e.onlyAgent(t).ID
}

// readUntil reads session output until it contains want.
func readUntil(t *testing.T, recv func() ([]byte, error), want string) string {
	t.Helper()
	var out strings.Builder
	done := make(chan struct{})
	go func() {
		defer close(done)
		for !strings.Contains(out.String(), want) {
			b, err := recv()
			if err != nil {
				return
			}
			out.Write(b)
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
	}
	if !strings.Contains(out.String(), want) {
		t.Fatalf("output lacks %q: %q", want, out.String())
	}
	return out.String()
}

func TestShellSessionThroughBroker(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux pseudo-terminal")
	}
	e := start(t)
	broker := e.broker(t)
	v := e.publish(t, filepath.Join(repoRoot(t), "modules", "shell"))
	agentID := shellAgent(t, e, true)
	jobID := e.queue(t, agentID, v, "open", `{"minutes":5}`)

	stream, err := broker.Attach(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	stream.Send(&openrmmv1.ShellFrame{TenantId: e.tenant, JobId: jobID})
	recv := func() ([]byte, error) {
		f, err := stream.Recv()
		return f.GetData(), err
	}
	readUntil(t, recv, "open-rmm: interactive session")
	stream.Send(&openrmmv1.ShellFrame{Cols: 100, Rows: 40})
	stream.Send(&openrmmv1.ShellFrame{Data: []byte("stty size; echo hello-$((40+2))\r")})
	out := readUntil(t, recv, "hello-42")
	if !strings.Contains(out, "40 100") {
		t.Errorf("resize not applied: %q", out)
	}
	// A second attachment is refused while the first is on.
	other, _ := broker.Attach(context.Background())
	other.Send(&openrmmv1.ShellFrame{TenantId: e.tenant, JobId: jobID})
	if _, err := other.Recv(); err == nil || !strings.Contains(err.Error(), "already attached") {
		t.Fatalf("second attachment: %v", err)
	}
	stream.Send(&openrmmv1.ShellFrame{Close: true})
	j := e.waitFinal(t, jobID)
	if j.State != store.JobSucceeded || !strings.Contains(string(j.Result), `"ended":"closed"`) {
		t.Fatalf("job = %s %s %s", j.State, j.Error, j.Result)
	}
	// Another tenant cannot attach to a session.
	jobID2 := e.queue(t, agentID, v, "open", `{"minutes":5}`)
	waitFor(t, func() bool {
		j, _ := e.store.GetJob(context.Background(), e.tenant, jobID2)
		return j.State == store.JobRunning
	})
	wrong, _ := broker.Attach(context.Background())
	wrong.Send(&openrmmv1.ShellFrame{TenantId: ids.NewUUID(), JobId: jobID2})
	if _, err := wrong.Recv(); err == nil {
		t.Fatal("attached from another tenant")
	}
}

func TestShellRefusedByLocalPolicy(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux pseudo-terminal")
	}
	e := start(t)
	v := e.publish(t, filepath.Join(repoRoot(t), "modules", "shell"))
	agentID := shellAgent(t, e, false)
	j := e.waitFinal(t, e.queue(t, agentID, v, "open", "{}"))
	if j.State != store.JobRejected || !strings.Contains(j.Error, "disabled by local policy") {
		t.Fatalf("job = %s %s", j.State, j.Error)
	}
}

// consoleOn starts a web console on the gateway's store and job key, so that
// its commands reach the env's agents.
func consoleOn(t *testing.T, e *env, broker openrmmv1.ShellBrokerServiceClient, opts ...consoleOpt) *consoleEnv {
	t.Helper()
	ctx := context.Background()
	tid := ids.NewUUID()
	idp := newIdP(t, tid, "console-app")
	cfg := authn.Config{Issuer: idp.srv.URL, ClientID: "console-app", MFAClaim: "amr",
		TenantMap: map[string][]string{tid: {e.tenant}}, MaxAuthAge: 10 * time.Minute}
	v, err := authn.NewVerifier(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	sgv, _ := authn.NewVerifier(ctx, cfg)
	sockDir, _ := os.MkdirTemp("", "sg")
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	sg, err := signer.New(e.jobSigner, sgv, filepath.Join(sockDir, "used.json"), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	lis, _ := net.Listen("unix", filepath.Join(sockDir, "s.sock"))
	gs := grpc.NewServer()
	openrmmv1.RegisterSignerServiceServer(gs, sg)
	go gs.Serve(lis)
	t.Cleanup(gs.Stop)
	conn, _ := grpc.NewClient("unix://"+lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	t.Cleanup(func() { conn.Close() })
	console := httptest.NewUnstartedServer(nil)
	console.StartTLS()
	t.Cleanup(console.Close)
	wcfg := web.Config{Store: e.store, Verifier: v, Signer: openrmmv1.NewSignerServiceClient(conn), PublicURL: console.URL,
		ClientSecret: "secret", Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), HTTPClient: http.DefaultClient, Shell: broker}
	for _, o := range opts {
		o(&wcfg, sg, e.tenant)
	}
	ws, err := web.New(wcfg)
	if err != nil {
		t.Fatal(err)
	}
	console.Config.Handler = ws.Handler()
	if wcfg.Uplink != nil {
		wcfg.Uplink.Handler = ws.LinkHandler()
		uctx, cancel := context.WithCancel(ctx)
		t.Cleanup(cancel)
		go wcfg.Uplink.Run(uctx)
	}
	return &consoleEnv{store: e.store, idp: idp, console: console, tenant: e.tenant}
}

// dialShell opens the terminal WebSocket of a session as the browser does.
func dialShell(t *testing.T, ce *consoleEnv, c *http.Client, jobID, origin string) (*websocket.Conn, error) {
	u, _ := url.Parse(ce.console.URL)
	wcfg, _ := websocket.NewConfig("wss://"+u.Host+"/shell/"+jobID+"/ws", origin)
	wcfg.TlsConfig = &tls.Config{RootCAs: ce.console.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs}
	for _, ck := range c.Jar.Cookies(u) {
		wcfg.Header.Add("Cookie", ck.Name+"="+ck.Value)
	}
	return websocket.DialConfig(wcfg)
}

func TestConsoleShell(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux pseudo-terminal")
	}
	e := start(t)
	broker := e.broker(t)
	e.publish(t, filepath.Join(repoRoot(t), "modules", "shell"))
	agentID := shellAgent(t, e, true)
	ce := consoleOn(t, e, broker)
	c, csrf := ce.loginTo(t, admin)

	// The agent page offers the shell; opening it needs the step-up.
	if _, body := get(t, c, ce.console.URL+"/agents/"+agentID); !strings.Contains(body, `action="/agents/`+agentID+`/shell"`) {
		t.Fatal("no shell button")
	}
	code, body, final := post(t, c, ce.console.URL+"/agents/"+agentID+"/shell", url.Values{"csrf": {csrf}, "minutes": {"15"}})
	if code != 200 || !strings.HasPrefix(final.Path, "/shell/") || !strings.Contains(body, `id="terminal"`) {
		t.Fatalf("open shell: %d at %s", code, final)
	}
	ce.idp.mu.Lock()
	auth := ce.idp.lastAuth
	ce.idp.mu.Unlock()
	if auth.Get("prompt") != "login" {
		t.Fatal("no step-up for the shell")
	}
	jobID := strings.TrimPrefix(final.Path, "/shell/")

	// Another origin is refused.
	if _, err := dialShell(t, ce, c, jobID, "https://evil.example"); err == nil {
		t.Fatal("cross-origin WebSocket accepted")
	}
	ws, err := dialShell(t, ce, c, jobID, ce.console.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	recv := func() ([]byte, error) {
		var b []byte
		err := websocket.Message.Receive(ws, &b)
		return b, err
	}
	readUntil(t, recv, "open-rmm: interactive session")
	in, _ := json.Marshal(map[string]string{"t": "i", "d": "echo hi-$((6*7))\r"})
	websocket.Message.Send(ws, string(in))
	readUntil(t, recv, "hi-42")
	websocket.Message.Send(ws, `{"t":"c"}`)
	j := e.waitFinal(t, jobID)
	if j.State != store.JobSucceeded {
		t.Fatalf("job = %s %s", j.State, j.Error)
	}

	// Every line typed is in the audit log.
	waitFor(t, func() bool {
		events, _ := e.store.ListAudit(context.Background(), e.tenant)
		for _, ev := range events {
			if ev.Action == "shell.input" && ev.Details["line"] == "echo hi-$((6*7))" {
				return true
			}
		}
		return false
	})

	// Only the operator who approved the session may open it.
	other := admin
	other.OID, other.Username = ids.NewUUID(), "luigi@cliente.it"
	oc, _ := ce.loginTo(t, other)
	if code, _ := get(t, oc, ce.console.URL+"/shell/"+jobID); code != http.StatusNotFound {
		t.Fatalf("another operator opened the session page: %d", code)
	}
	// The shell module is not a generic command, nor allowed in policies.
	if _, body := get(t, c, ce.console.URL+"/agents/"+agentID); strings.Contains(body, `value="shell|`) {
		t.Fatal("shell offered as a generic command")
	}
}

// loginTo signs u in and returns the browser and the CSRF token.
func (e *consoleEnv) loginTo(t *testing.T, u opIdentity) (*http.Client, string) {
	t.Helper()
	e.idp.signIn(u)
	c := e.browser(t)
	code, body := get(t, c, e.console.URL+"/agents")
	if code != 200 {
		t.Fatalf("login: %d %s", code, body)
	}
	return c, csrfFrom(t, body)
}

func TestFederatedShell(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux pseudo-terminal")
	}
	var hub *federation.Hub
	central := startConsole(t, withHub(t, &hub))
	e := start(t)
	broker := e.broker(t)
	e.publish(t, filepath.Join(repoRoot(t), "modules", "shell"))
	agentID := shellAgent(t, e, true)
	customer := consoleOn(t, e, broker, withCentral(t, central, ""))
	central.idp.signIn(mspAdmin)
	c, _, _ := link(t, central, customer, hub)

	_, body := get(t, c, central.console.URL+"/agents/"+agentID)
	csrf := csrfFrom(t, body)
	code, _, final := post(t, c, central.console.URL+"/agents/"+agentID+"/shell", url.Values{"csrf": {csrf}, "minutes": {"15"}})
	if code != 200 || !strings.HasPrefix(final.Path, "/shell/") {
		t.Fatalf("open shell from the central console: %d at %s", code, final)
	}
	jobID := strings.TrimPrefix(final.Path, "/shell/")
	if _, err := dialShell(t, central, c, jobID, "https://evil.example"); err == nil {
		t.Fatal("cross-origin WebSocket accepted by the central console")
	}
	ws, err := dialShell(t, central, c, jobID, central.console.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	recv := func() ([]byte, error) {
		var b []byte
		err := websocket.Message.Receive(ws, &b)
		return b, err
	}
	readUntil(t, recv, "open-rmm: interactive session")
	websocket.Message.Send(ws, `{"t":"i","d":"echo fed-$((40+2))\r"}`)
	readUntil(t, recv, "fed-42")
	websocket.Message.Send(ws, `{"t":"c"}`)
	if j := e.waitFinal(t, jobID); j.State != store.JobSucceeded {
		t.Fatalf("job = %s %s", j.State, j.Error)
	}
	waitFor(t, func() bool {
		events, _ := e.store.ListAudit(context.Background(), e.tenant)
		for _, ev := range events {
			if ev.Action == "shell.input" && strings.Contains(ev.Actor, "via central console") && ev.Details["line"] == "echo fed-$((40+2))" {
				return true
			}
		}
		return false
	})
}

// TestShellPreview serves a console with a live agent and the shell module,
// to try the terminal in a browser:
//
//	OPENRMM_PREVIEW=shell go test -run ShellPreview -timeout 0 ./internal/e2e/
//
// then open http://127.0.0.1:18081 and the agent's page.
func TestShellPreview(t *testing.T) {
	if os.Getenv("OPENRMM_PREVIEW") != "shell" {
		t.Skip("set OPENRMM_PREVIEW=shell")
	}
	e := start(t)
	broker := e.broker(t)
	e.publish(t, filepath.Join(repoRoot(t), "modules", "shell"))
	shellAgent(t, e, true)
	ce := consoleOn(t, e, broker)
	ce.idp.signIn(admin)
	ctx := context.Background()
	tid := ce.idp.tid
	v, err := authn.NewVerifier(ctx, authn.Config{Issuer: ce.idp.srv.URL, ClientID: "console-app", MFAClaim: "amr",
		TenantMap: map[string][]string{tid: {e.tenant}}, MaxAuthAge: 10 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	sockDir, _ := os.MkdirTemp("", "sg")
	defer os.RemoveAll(sockDir)
	sgv, _ := authn.NewVerifier(ctx, authn.Config{Issuer: ce.idp.srv.URL, ClientID: "console-app", MFAClaim: "amr",
		TenantMap: map[string][]string{tid: {e.tenant}}, MaxAuthAge: 10 * time.Minute})
	sg, _ := signer.New(e.jobSigner, sgv, filepath.Join(sockDir, "used.json"), slog.New(slog.NewTextHandler(io.Discard, nil)))
	lis, _ := net.Listen("unix", filepath.Join(sockDir, "s.sock"))
	gs := grpc.NewServer()
	openrmmv1.RegisterSignerServiceServer(gs, sg)
	go gs.Serve(lis)
	defer gs.Stop()
	conn, _ := grpc.NewClient("unix://"+lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	defer conn.Close()
	ws, err := web.New(web.Config{Store: e.store, Verifier: v, Signer: openrmmv1.NewSignerServiceClient(conn),
		PublicURL: "http://127.0.0.1:18081", ClientSecret: "secret", Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		HTTPClient: http.DefaultClient, Shell: broker})
	if err != nil {
		t.Fatal(err)
	}
	hl, err := net.Listen("tcp", "127.0.0.1:18081")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("shell preview on http://127.0.0.1:18081")
	http.Serve(hl, ws.Handler())
}
