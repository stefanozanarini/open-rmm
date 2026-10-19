package e2e

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/open-rmm/internal/agent/identity"
	"github.com/stefanozanarini/open-rmm/internal/console/gateway"
	"github.com/stefanozanarini/open-rmm/internal/console/relay"
	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/ids"
	"github.com/stefanozanarini/open-rmm/internal/pki"
	"github.com/stefanozanarini/open-rmm/internal/tlsconf"
)

// viaRelay makes start() put a DMZ relay between agents and core.
var viaRelay bool

func silent() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// startRelay starts the gateway relay (agent listener + tunnel listener) and
// a core dialer serving gw on the tunnels. It returns the agent listener.
func startRelay(t *testing.T, ctx context.Context, e *env, gw *gateway.Server, root, ca *pki.CA, agentTLS *tls.Config) net.Listener {
	t.Helper()
	pool := relay.NewTunnelPool(silent())
	tunnelLis := tunnelListener(t, ctx, pool, ca, agentTLS)
	g, err := relay.NewGateway(pool, silent())
	if err != nil {
		t.Fatal(err)
	}
	as := g.AgentServer(credentials.NewTLS(agentTLS))
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go as.Serve(lis)
	t.Cleanup(func() { as.Stop(); g.Close() })

	coreCert, coreKey, err := ca.IssueCore(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	d := &relay.Dialer{Target: tunnelLis.Addr().String(), Log: silent(),
		TLS: relay.CoreTLS("localhost", root.Cert, tls.Certificate{Certificate: [][]byte{coreCert.Raw, ca.Cert.Raw}, PrivateKey: coreKey})}
	dctx, stopDialer := context.WithCancel(ctx)
	ts := gw.TunnelGRPCServer()
	go ts.Serve(d)
	go d.Run(dctx)
	waitFor(t, func() bool { return g.TunnelsUp() > 0 })
	// restartCore drops the tunnel (as when the core restarts) and opens a
	// new one with a fresh server.
	e.restartCore = func() {
		stopDialer()
		ts.Stop()
		waitFor(t, func() bool { return g.TunnelsUp() == 0 })
		d2 := &relay.Dialer{Target: d.Target, TLS: d.TLS, Log: silent()}
		ts = gw.TunnelGRPCServer()
		dctx, stopDialer = context.WithCancel(ctx)
		go ts.Serve(d2)
		go d2.Run(dctx)
		waitFor(t, func() bool { return g.TunnelsUp() > 0 })
	}
	t.Cleanup(func() { stopDialer(); ts.Stop() })
	e.relayGateway = g
	return lis
}

func TestAgentSurvivesCoreRestart(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("uses the sh entrypoint")
	}
	viaRelay = true
	defer func() { viaRelay = false }()
	e := start(t)
	v := e.publish(t, filepath.Join(repoRoot(t), "modules", "sysinfo"))
	_, agentID := startAgent(t, e, true)
	if j := e.waitFinal(t, e.queue(t, agentID, v, "info", "{}")); j.State != store.JobSucceeded {
		t.Fatalf("before restart: %s %s", j.State, j.Error)
	}
	e.restartCore()
	// The agent reconnects by itself (backoff starts at 2s).
	j := e.waitFinalWithin(t, e.queue(t, agentID, v, "info", "{}"), 30*time.Second)
	if j.State != store.JobSucceeded {
		t.Fatalf("after restart: %s %s", j.State, j.Error)
	}
}

func tunnelListener(t *testing.T, ctx context.Context, pool *relay.TunnelPool, ca *pki.CA, agentTLS *tls.Config) net.Listener {
	t.Helper()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	lis := tls.NewListener(raw, relay.TunnelTLS(agentTLS.Certificates[0], ca.Cert))
	go pool.Serve(ctx, lis)
	return lis
}

// The main scenarios, again, with the relay in between.
func TestViaRelay(t *testing.T) {
	viaRelay = true
	defer func() { viaRelay = false }()
	for name, fn := range map[string]func(*testing.T){
		"enroll and reconnect":     TestEnrollConnectAndReconnect,
		"spent token":              TestSpentTokenIsRefused,
		"certificate required":     TestAgentServiceRequiresCertificate,
		"revoked agent":            TestRevokedAgentIsRefused,
		"revocation closes stream": TestRevocationClosesOpenSession,
		"foreign certificate":      TestForeignCertificateIsRefused,
		"pinned root":              TestAgentRejectsServerNotChainingToPinnedRoot,
		"pending approval":         TestNewAgentWaitsForApproval,
		"automatic renewal":        TestAgentRenewsCertificateAutomatically,
		"sysinfo job":              TestSysinfoModuleEndToEnd,
		"jobs after approval":      TestPendingAgentGetsJobsOnlyAfterApproval,
		"agent update":             TestAgentStagesTargetedRelease,
		"package delivery":         TestPackageDeliveredToAgent,
		"shell session":            TestShellSessionThroughBroker,
	} {
		t.Run(name, fn)
	}
}

func TestRelayRefusesUnknownMethods(t *testing.T) {
	viaRelay = true
	defer func() { viaRelay = false }()
	e := start(t)
	cfg := e.agentConfig(t, e.tokenWith(t, 1, true))
	id := enrollOnly(t, e, cfg)
	conn, _ := grpc.NewClient(e.addr, grpc.WithTransportCredentials(credentials.NewTLS(
		tlsconf.Client("localhost", e.root.Cert, id.Cert, id.Chain, id.Key))))
	defer conn.Close()
	// An internal service must never be reachable from the internet side.
	_, err := openrmmv1.NewSignerServiceClient(conn).SignJob(context.Background(), &openrmmv1.SignJobRequest{})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("internal service through the relay: %v", err)
	}
}

// A compromised gateway can forward anything as "the client certificate":
// the core must still refuse identities that do not chain to its CA.
func TestCoreRejectsForgedForwardedIdentity(t *testing.T) {
	viaRelay = true
	defer func() { viaRelay = false }()
	e := start(t)
	// Our own "evil gateway": another tunnel listener the core dials.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv, srvKey, _ := e.ca.IssueServer([]string{"localhost"}, time.Now())
	evilTLS := tlsconf.Server(srv, []*x509.Certificate{e.ca.Cert}, srvKey, e.ca.Cert)
	pool := relay.NewTunnelPool(silent())
	tl := tunnelListener(t, ctx, pool, e.ca, evilTLS)
	coreCert, coreKey, _ := e.ca.IssueCore(time.Now())
	d := &relay.Dialer{Target: tl.Addr().String(), Log: silent(), Count: 1,
		TLS: relay.CoreTLS("localhost", e.root.Cert, tls.Certificate{Certificate: [][]byte{coreCert.Raw, e.ca.Cert.Raw}, PrivateKey: coreKey})}
	ts := e.gw.TunnelGRPCServer()
	go ts.Serve(d)
	go d.Run(ctx)
	defer ts.Stop()
	waitFor(t, func() bool { return pool.Len() > 0 })
	conn, err := pool.ClientConn()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// A certificate with a valid-looking identity, from another CA.
	otherRoot, _ := pki.NewRootCA("other", time.Now())
	otherCA, _ := pki.NewIntermediateCA(otherRoot, "other", time.Now())
	key, _ := identity.NewKey()
	csr, _ := identity.CSR(key, "evil")
	forged, _ := otherCA.IssueAgent(csr, pki.Identity{TenantID: e.tenant, AgentID: ids.NewUUID()}, time.Now())
	md := metadata.Pairs("x-openrmm-client-cert-bin", string(forged.Raw))
	stream, err := openrmmv1.NewAgentServiceClient(conn).Connect(metadata.NewOutgoingContext(context.Background(), md))
	if err == nil {
		_, err = stream.Recv()
	}
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("forged forwarded identity: %v", err)
	}
}

// Without the tunnel marker, forwarded metadata means nothing: a direct
// caller cannot claim an identity through headers.
func TestDirectServerIgnoresForwardedMetadata(t *testing.T) {
	e := start(t) // direct mode
	cfg := e.agentConfig(t, e.tokenWith(t, 1, true))
	id := enrollOnly(t, e, cfg)
	md := metadata.Pairs("x-openrmm-client-cert-bin", string(id.Cert.Raw))
	conn := dialNoCert(t, e)
	stream, err := openrmmv1.NewAgentServiceClient(conn).Connect(metadata.NewOutgoingContext(context.Background(), md))
	if err == nil {
		_, err = stream.Recv()
	}
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("identity claimed through metadata: %v", err)
	}
}

func TestTunnelRequiresCoreCertificate(t *testing.T) {
	viaRelay = true
	defer func() { viaRelay = false }()
	e := start(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv, srvKey, _ := e.ca.IssueServer([]string{"localhost"}, time.Now())
	pool := relay.NewTunnelPool(silent())
	tl := tunnelListener(t, ctx, pool, e.ca, tlsconf.Server(srv, []*x509.Certificate{e.ca.Cert}, srvKey, e.ca.Cert))
	// An agent certificate (valid, same CA) is not a core certificate.
	cfg := e.agentConfig(t, e.tokenWith(t, 1, true))
	id := enrollOnly(t, e, cfg)
	c, err := tls.Dial("tcp", tl.Addr().String(), relay.CoreTLS("localhost", e.root.Cert,
		tls.Certificate{Certificate: [][]byte{id.Cert.Raw, e.ca.Cert.Raw}, PrivateKey: id.Key}))
	if err == nil {
		// TLS 1.3 reports client-certificate rejection on the first read.
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err = c.Read(make([]byte, 1))
		c.Close()
	}
	if err == nil {
		t.Fatal("tunnel accepted an agent certificate")
	}
	time.Sleep(200 * time.Millisecond)
	if pool.Len() != 0 {
		t.Fatal("agent connection admitted as a tunnel")
	}
}
