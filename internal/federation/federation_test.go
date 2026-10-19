package federation

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/ids"
)

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatal("condition not met")
}

type env struct {
	central  *store.Memory
	customer *store.Memory
	hub      *Hub
	addr     string
	tenant   string
}

func start(t *testing.T) *env {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	e := &env{central: store.NewMemory(), customer: store.NewMemory(), tenant: ids.NewUUID()}
	e.central.CreateTenant(ctx, store.Tenant{ID: e.tenant, Name: "MSP"})
	id, err := CentralIdentity(ctx, e.central, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := CentralIdentity(ctx, e.central, time.Now()); again.Fingerprint != id.Fingerprint {
		t.Fatal("central identity not persistent")
	}
	e.hub = &Hub{Store: e.central, ID: id, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	e.addr = lis.Addr().String()
	go e.hub.Serve(ctx, lis)
	return e
}

func (e *env) newLink(t *testing.T, name string) (store.FederationLink, string) {
	tok := ids.NewSecret(32)
	exp := time.Now().Add(TokenTTL)
	l := store.FederationLink{ID: ids.NewUUID(), TenantID: e.tenant, Name: name, TokenExpiresAt: &exp, CreatedBy: "t"}
	if err := e.central.CreateLink(context.Background(), l, store.HashToken(tok)); err != nil {
		t.Fatal(err)
	}
	return l, Bundle{Addr: e.addr, Fingerprint: e.hub.ID.Fingerprint, Token: tok}.Encode()
}

func TestLinkEndToEnd(t *testing.T) {
	e := start(t)
	ctx := context.Background()
	link, bundle := e.newLink(t, "Cliente A")

	up, err := Join(ctx, bundle, "admin", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if up.LinkID != link.ID {
		t.Fatalf("link id %s, want %s", up.LinkID, link.ID)
	}
	// The token is single use.
	if _, err := Join(ctx, bundle, "admin", time.Now()); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("token reused: %v", err)
	}
	e.customer.PutUplink(ctx, up)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == PathSummary {
			json.NewEncoder(w).Encode(Summary{Console: "Cliente A", Agents: 12, Online: 10})
			return
		}
		op, _ := ParseOperator(r.Header.Get(HeaderOperator))
		io.WriteString(w, r.Method+" "+r.URL.Path+" as "+op.Username)
	})
	u := &Uplink{Store: e.customer, Handler: handler, Log: e.hub.Log, Poll: 50 * time.Millisecond}
	uctx, ucancel := context.WithCancel(ctx)
	defer ucancel()
	go u.Run(uctx)
	waitFor(t, func() bool { return e.hub.Connected(link.ID) == tunnelsPerLink })

	req, _ := http.NewRequest(http.MethodPost, URL+"/agents/x/notes", strings.NewReader("a=b"))
	req.Header.Set(HeaderOperator, Operator{ObjectID: ids.NewUUID(), TenantID: ids.NewUUID(), Username: "mario@msp.it",
		Session: ids.NewSecret(32)}.Encode())
	resp, err := e.hub.Client(link.ID).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "POST /agents/x/notes as mario@msp.it" {
		t.Fatalf("body = %q", body)
	}
	if err := e.hub.FetchSummary(ctx, link.ID); err != nil {
		t.Fatal(err)
	}
	got, _ := e.central.GetLink(ctx, e.tenant, link.ID)
	var s Summary
	if json.Unmarshal(got.Summary, &s); s.Agents != 12 || got.LastSeenAt == nil {
		t.Fatalf("summary = %+v", got)
	}

	// Suspending at the customer closes the tunnels.
	e.customer.SetUplinkSuspended(ctx, true)
	waitFor(t, func() bool { return u.Up() == 0 })
	e.hub.Drop(link.ID)
	waitFor(t, func() bool { return e.hub.Connected(link.ID) == 0 })
	rctx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	req, _ = http.NewRequestWithContext(rctx, http.MethodGet, URL+"/agents", nil)
	if _, err := e.hub.Client(link.ID).Do(req); err == nil {
		t.Fatal("request through a suspended link")
	}

	// Resumed, then revoked at the central console: tunnels are refused.
	e.customer.SetUplinkSuspended(ctx, false)
	waitFor(t, func() bool { return e.hub.Connected(link.ID) > 0 })
	e.central.RevokeLink(ctx, e.tenant, link.ID)
	e.hub.Drop(link.ID)
	time.Sleep(300 * time.Millisecond)
	if n := e.hub.Connected(link.ID); n != 0 {
		t.Fatalf("%d tunnels of a revoked link", n)
	}
}

func TestJoinChecksThePin(t *testing.T) {
	e := start(t)
	_, bundle := e.newLink(t, "Cliente B")
	b, _ := ParseBundle(bundle)
	b.Fingerprint = strings.Repeat("0", 64)
	if _, err := Join(context.Background(), b.Encode(), "admin", time.Now()); err == nil || !strings.Contains(err.Error(), "pinned") {
		t.Fatalf("wrong pin accepted: %v", err)
	}
	if _, err := ParseBundle("ormm-link-1.xyz"); err == nil {
		t.Fatal("damaged bundle accepted")
	}
}

func TestOperatorHeader(t *testing.T) {
	o := Operator{ObjectID: ids.NewUUID(), TenantID: ids.NewUUID(), Username: "a@b", Roles: []string{"OpenRMM.Admin"}, Session: ids.NewSecret(32)}
	got, err := ParseOperator(o.Encode())
	if err != nil || got.Username != "a@b" || got.Roles[0] != "OpenRMM.Admin" {
		t.Fatalf("operator = %+v, %v", got, err)
	}
	o.Session = "short"
	if _, err := ParseOperator(o.Encode()); err == nil {
		t.Fatal("short session accepted")
	}
}
