package e2e

import (
	"context"
	"html"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/open-rmm/internal/console/authn"
	"github.com/stefanozanarini/open-rmm/internal/console/signer"
	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/console/web"
	"github.com/stefanozanarini/open-rmm/internal/federation"
	"github.com/stefanozanarini/open-rmm/internal/ids"
	"google.golang.org/protobuf/proto"
)

// withHub makes a console central: it accepts links on a local listener.
func withHub(t *testing.T, hub **federation.Hub) consoleOpt {
	return func(cfg *web.Config, _ *signer.Server, _ string) {
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		st := cfg.Store.(*store.Memory)
		id, err := federation.CentralIdentity(ctx, st, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		h := &federation.Hub{Store: st, ID: id, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), DialWait: 500 * time.Millisecond}
		lis, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go h.Serve(ctx, lis)
		cfg.Hub, cfg.LinkAddr, *hub = h, lis.Addr().String(), h
	}
}

// withCentral makes a console trust a central console's directory, in the
// web console and in the signer.
func withCentral(t *testing.T, central *consoleEnv, maxRole string) consoleOpt {
	return func(cfg *web.Config, sg *signer.Server, tenant string) {
		fc := authn.Config{Issuer: central.idp.srv.URL, ClientID: central.idp.clientID, MFAClaim: "amr",
			TenantMap: map[string][]string{central.idp.tid: {tenant}}, MaxAuthAge: 10 * time.Minute, MaxRole: maxRole}
		v, err := authn.NewVerifier(context.Background(), fc)
		if err != nil {
			t.Fatal(err)
		}
		sv, _ := authn.NewVerifier(context.Background(), fc)
		sg.Trust(sv)
		cfg.FedVerifier = v
		cfg.Uplink = &federation.Uplink{Store: cfg.Store.(*store.Memory), Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
			Poll: 50 * time.Millisecond}
	}
}

var bundleRe = regexp.MustCompile(`ormm-link-1\.[A-Za-z0-9_-]+`)

var mspAdmin = opIdentity{OID: ids.NewUUID(), Name: "Luca Bianchi", Username: "luca@msp.it",
	Roles: []string{authn.RoleAdmin}, AMR: []string{"pwd", "mfa"}}

// link creates a link on central, joins it from customer and opens it.
func link(t *testing.T, central, customer *consoleEnv, hub *federation.Hub) (*http.Client, string, store.FederationLink) {
	t.Helper()
	ctx := context.Background()
	c, csrf := central.login(t, mspAdmin)
	_, body, _ := post(t, c, central.console.URL+"/federation/links", url.Values{"csrf": {csrf}, "name": {"Cliente Alfa"}})
	bundle := bundleRe.FindString(body)
	if bundle == "" {
		t.Fatalf("no link token: %s", body)
	}
	cc, ccsrf := customer.loginTo(t, admin)
	if _, body, _ = post(t, cc, customer.console.URL+"/federation/join", url.Values{"csrf": {ccsrf}, "bundle": {bundle}}); !strings.Contains(body, "Console collegata") {
		t.Fatalf("join: %s", body)
	}
	links, _ := central.store.ListLinks(ctx, central.tenant)
	if len(links) != 1 || links[0].Status != store.LinkActive {
		t.Fatalf("links = %+v", links)
	}
	waitFor(t, func() bool { return hub.Connected(links[0].ID) > 0 })
	post(t, c, central.console.URL+"/federation/open", url.Values{"csrf": {csrf}, "link": {links[0].ID}})
	return c, csrf, links[0]
}

func TestFederationFullOperations(t *testing.T) {
	var hub *federation.Hub
	central := startConsole(t, withHub(t, &hub))
	customer := startConsole(t, withCentral(t, central, ""))
	customer.addWindowsAgent(t, "PC-CLIENTE")
	central.idp.signIn(mspAdmin)
	c, _, l := link(t, central, customer, hub)

	// The pages are the customer's, with a banner.
	_, body := get(t, c, central.console.URL+"/agents")
	if !strings.Contains(body, "PC-CLIENTE") || !strings.Contains(body, "tramite la console centrale") {
		t.Fatalf("customer page not shown: %s", body)
	}
	csrf := csrfFrom(t, body)

	// An action is done by the customer console, audited there.
	code, _, _ := post(t, c, central.console.URL+"/agents/"+customer.agentID+"/approve", url.Values{"csrf": {csrf}})
	a, _ := customer.store.GetAgent(context.Background(), customer.tenant, customer.agentID)
	if code != 200 || a.Status != store.AgentActive || !strings.Contains(a.ApprovedBy, mspAdmin.Username) {
		t.Fatalf("approve through the link: %d %s by %q", code, a.Status, a.ApprovedBy)
	}
	events, _ := customer.store.ListAudit(context.Background(), customer.tenant)
	found := false
	for _, ev := range events {
		found = found || (ev.Action == "agent.approved" && strings.Contains(ev.Actor, "luca@msp.it") && strings.Contains(ev.Actor, "via central console"))
	}
	if !found {
		t.Fatal("approval not audited on the customer console as a central operator")
	}

	// A command: step-up on the central directory, signed by the customer's signer.
	code, body, final := post(t, c, central.console.URL+"/agents/"+customer.agentID+"/jobs",
		url.Values{"csrf": {csrf}, "target": {"sysinfo|1.0.0|info"}, "params": {"{}"}, "ttl_minutes": {"60"}})
	if code != 200 || !strings.HasPrefix(final.Path, "/jobs/") {
		t.Fatalf("job through the link: %d at %s: %s", code, final, body)
	}
	central.idp.mu.Lock()
	auth := central.idp.lastAuth
	central.idp.mu.Unlock()
	if auth.Get("prompt") != "login" || !strings.HasPrefix(auth.Get("nonce"), "job.") {
		t.Fatalf("step-up authorize params: %v", auth)
	}
	j, err := customer.store.GetJob(context.Background(), customer.tenant, strings.TrimPrefix(final.Path, "/jobs/"))
	if err != nil || !strings.Contains(j.CreatedBy, mspAdmin.Username) {
		t.Fatalf("job = %+v, %v", j, err)
	}
	env := &openrmmv1.SignedEnvelope{}
	proto.Unmarshal(j.Envelope, env)
	if err := customer.jobKeys.Verify("openrmm/job/v1", env.GetKeyId(), env.GetPayload(), env.GetSignature()); err != nil {
		t.Fatalf("job not signed by the customer's signer: %v", err)
	}
	if _, err := central.store.GetJob(context.Background(), central.tenant, j.ID); err == nil {
		t.Fatal("job stored on the central console")
	}

	// The summary reaches the central dashboard.
	if err := hub.FetchSummary(context.Background(), l.ID); err != nil {
		t.Fatal(err)
	}
	post(t, c, central.console.URL+"/federation/close", url.Values{"csrf": {csrfOf(t, c, central)}})
	_, body = get(t, c, central.console.URL+"/federation")
	if !strings.Contains(body, "Cliente Alfa") || !strings.Contains(body, "connessa") {
		t.Fatalf("links page: %s", body)
	}
	if _, body = get(t, c, central.console.URL+"/agents"); strings.Contains(body, "PC-CLIENTE") {
		t.Fatal("still on the customer console after closing")
	}

	// The link settings are never reachable from the central console.
	req, _ := http.NewRequest(http.MethodPost, federation.URL+"/federation/uplink/resume", nil)
	req.Header.Set(federation.HeaderOperator, federation.Operator{ObjectID: mspAdmin.OID, TenantID: central.idp.tid,
		Username: mspAdmin.Username, Roles: mspAdmin.Roles, Session: ids.NewSecret(32)}.Encode())
	resp, err := hub.Client(l.ID).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("link settings over the link: %d", resp.StatusCode)
	}

	// Kill switch at the customer.
	cc, ccsrf := customer.login(t, admin)
	post(t, cc, customer.console.URL+"/federation/uplink/suspend", url.Values{"csrf": {ccsrf}})
	waitFor(t, func() bool { return hub.Connected(l.ID) == 0 })
	post(t, c, central.console.URL+"/federation/open", url.Values{"csrf": {csrfOf(t, c, central)}, "link": {l.ID}})
	_, body, final = post(t, c, central.console.URL+"/agents/"+customer.agentID+"/revoke", url.Values{"csrf": {csrf}})
	if final.Path != "/federation" || !strings.Contains(html.UnescapeString(body), "non è raggiungibile") {
		t.Fatalf("suspended link: at %s", final)
	}
	if a, _ := customer.store.GetAgent(context.Background(), customer.tenant, customer.agentID); a.Status != store.AgentActive {
		t.Fatal("action went through a suspended link")
	}
}

// csrfOf returns the CSRF token of the central console's own pages.
func csrfOf(t *testing.T, c *http.Client, central *consoleEnv) string {
	_, body := get(t, c, central.console.URL+"/federation")
	return csrfFrom(t, body)
}

func TestFederationRoleCapAndUntrustedSigner(t *testing.T) {
	var hub *federation.Hub
	central := startConsole(t, withHub(t, &hub))
	// Read-only delegation.
	customer := startConsole(t, withCentral(t, central, authn.RoleReader))
	central.idp.signIn(mspAdmin)
	c, _, _ := link(t, central, customer, hub)
	_, body := get(t, c, central.console.URL+"/agents")
	csrf := csrfFrom(t, body)
	if code, _, _ := post(t, c, central.console.URL+"/agents/"+customer.agentID+"/approve", url.Values{"csrf": {csrf}}); code != http.StatusForbidden {
		t.Fatalf("reader approved an agent: %d", code)
	}
	if strings.Contains(body, `action="/tokens"`) || strings.Contains(body, `href="/tokens"`) {
		t.Fatal("admin menu shown to a capped operator")
	}
}
