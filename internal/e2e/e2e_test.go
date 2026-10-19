// Package e2e runs a real gateway (TLS on a local port, in-memory store)
// against the real agent client.
package e2e

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/open-rmm/internal/agent/client"
	"github.com/stefanozanarini/open-rmm/internal/agent/config"
	"github.com/stefanozanarini/open-rmm/internal/agent/identity"
	"github.com/stefanozanarini/open-rmm/internal/console/audit"
	"github.com/stefanozanarini/open-rmm/internal/console/gateway"
	"github.com/stefanozanarini/open-rmm/internal/console/relay"
	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/ids"
	"github.com/stefanozanarini/open-rmm/internal/pki"
	"github.com/stefanozanarini/open-rmm/internal/signing"
	"github.com/stefanozanarini/open-rmm/internal/tlsconf"
)

type env struct {
	// offset shifts the gateway clock, e.g. to issue certificates "in the past".
	offset atomic.Int64
	// jobSigner and moduleSigner stand in for the signing service and the
	// offline module release key.
	jobSigner     *signing.Signer
	moduleSigner  *signing.Signer
	releaseSigner *signing.Signer
	relayGateway  *relay.Gateway
	restartCore   func()
	root          *pki.CA
	ca            *pki.CA
	store         *store.Memory
	gw            *gateway.Server
	addr          string
	tenant        string
}

func quietLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func start(t *testing.T) *env {
	t.Helper()
	now := time.Now()
	root, err := pki.NewRootCA("root", now)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := pki.NewIntermediateCA(root, "agents", now)
	if err != nil {
		t.Fatal(err)
	}
	srv, srvKey, err := ca.IssueServer([]string{"localhost"}, now)
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewMemory()
	tenant := ids.NewUUID()
	if err := st.CreateTenant(context.Background(), store.Tenant{ID: tenant, Name: "test"}); err != nil {
		t.Fatal(err)
	}
	e := &env{}
	gw, err := gateway.New(gateway.Config{Store: st, AgentsCA: ca, Logger: quietLog(), HeartbeatInterval: 10 * time.Second,
		Now: func() time.Time { return time.Now().Add(time.Duration(e.offset.Load())) }})
	if err != nil {
		t.Fatal(err)
	}
	runCtx, stopRun := context.WithCancel(context.Background())
	t.Cleanup(stopRun)
	agentTLS := tlsconf.Server(srv, []*x509.Certificate{ca.Cert}, srvKey, ca.Cert)
	var lis net.Listener
	if viaRelay {
		// Agents talk to the relay; the core opens the tunnels to it.
		lis = startRelay(t, runCtx, e, gw, root, ca, agentTLS)
	} else {
		gs := gw.GRPCServer(agentTLS)
		lis, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go gs.Serve(lis)
		t.Cleanup(gs.Stop)
	}
	go gw.Run(runCtx)
	e.jobSigner, e.moduleSigner, e.releaseSigner = newSigner(t), newSigner(t), newSigner(t)
	_, port, _ := net.SplitHostPort(lis.Addr().String())
	e.root, e.ca, e.store, e.gw, e.addr, e.tenant = root, ca, st, gw, "localhost:"+port, tenant
	return e
}

func (e *env) token(t *testing.T, maxUses int) string {
	return e.tokenWith(t, maxUses, false)
}

func (e *env) tokenWith(t *testing.T, maxUses int, autoApprove bool) string {
	t.Helper()
	secret := ids.NewSecret(32)
	if err := e.store.CreateEnrollmentToken(context.Background(), store.EnrollmentToken{
		ID: ids.NewUUID(), TenantID: e.tenant, MaxUses: maxUses, ExpiresAt: time.Now().Add(time.Hour),
		AutoApprove: autoApprove,
	}, store.HashToken(secret)); err != nil {
		t.Fatal(err)
	}
	return secret
}

func (e *env) agentConfig(t *testing.T, token string) *config.Config {
	t.Helper()
	dir := t.TempDir()
	rootFile := filepath.Join(dir, "root-ca.crt")
	if err := os.WriteFile(rootFile, pki.EncodeCertPEM(e.root.Cert), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgFile := filepath.Join(dir, "agent.json")
	data := `{"server":"` + e.addr + `","root_ca_file":"root-ca.crt","enroll_token":"` + token +
		`","data_dir":"` + filepath.Join(dir, "data") + `","install_dir":"` + filepath.Join(dir, "install") + `",` + e.keysJSON() + `}`
	if err := os.WriteFile(cfgFile, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgFile)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// runAgent starts the agent and waits for its first successful connection.
func runAgent(t *testing.T, cfg *config.Config) context.CancelFunc {
	t.Helper()
	return runAgentVersion(t, cfg, "test")
}

func runAgentVersion(t *testing.T, cfg *config.Config, version string) context.CancelFunc {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	connected := make(chan struct{}, 1)
	c := client.New(cfg, version, quietLog())
	c.OnConnected = func() {
		select {
		case connected <- struct{}{}:
		default:
		}
	}
	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	select {
	case <-connected:
	case <-time.After(10 * time.Second):
		t.Fatal("agent did not connect")
	}
	return cancel
}

func TestEnrollConnectAndReconnect(t *testing.T) {
	e := start(t)
	cfg := e.agentConfig(t, e.token(t, 1))
	stop := runAgent(t, cfg)

	agents, _ := e.store.ListAgents(context.Background(), e.tenant)
	if len(agents) != 1 {
		t.Fatalf("got %d agents", len(agents))
	}
	a := agents[0]
	if a.LastSeenAt == nil || a.Host.Hostname == "" || a.Host.AgentVersion != "test" {
		t.Fatalf("agent not updated on hello: %+v", a)
	}
	waitFor(t, func() bool { return e.gw.ConnectedAgents() == 1 })
	stop()

	// A restarted agent reuses its identity: the single-use token is spent,
	// so reconnecting proves the stored certificate works.
	runAgent(t, cfg)
	agents, _ = e.store.ListAgents(context.Background(), e.tenant)
	if len(agents) != 1 {
		t.Fatalf("restart created a new agent: %d agents", len(agents))
	}

	events, _ := e.store.ListAudit(context.Background(), e.tenant)
	if len(events) != 1 || events[0].Action != "agent.enrolled" {
		t.Fatalf("audit = %+v", events)
	}
	if err := audit.VerifyChain(events); err != nil {
		t.Fatal(err)
	}
}

func TestSpentTokenIsRefused(t *testing.T) {
	e := start(t)
	tok := e.token(t, 1)
	runAgent(t, e.agentConfig(t, tok))
	conn := dialNoCert(t, e)
	_, err := openrmmv1.NewEnrollmentServiceClient(conn).Enroll(context.Background(), enrollReq(t, tok))
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("second enrollment: %v", err)
	}
}

func TestAgentServiceRequiresCertificate(t *testing.T) {
	e := start(t)
	conn := dialNoCert(t, e)
	stream, err := openrmmv1.NewAgentServiceClient(conn).Connect(context.Background())
	if err == nil {
		_, err = stream.Recv()
	}
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("connect without certificate: %v", err)
	}
}

func TestRevokedAgentIsRefused(t *testing.T) {
	e := start(t)
	cfg := e.agentConfig(t, e.token(t, 1))
	stop := runAgent(t, cfg)
	stop()
	agents, _ := e.store.ListAgents(context.Background(), e.tenant)
	if err := e.store.SetAgentStatus(context.Background(), e.tenant, agents[0].ID, store.AgentRevoked); err != nil {
		t.Fatal(err)
	}
	if err := connectOnce(t, e, cfg); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("revoked agent: %v", err)
	}
}

func TestRevocationClosesOpenSession(t *testing.T) {
	restore := gateway.SetCheckIntervalForTest(0)
	defer restore()
	e := start(t)
	cfg := e.agentConfig(t, e.token(t, 1))
	id := enrollOnly(t, e, cfg)
	conn, err := grpc.NewClient(cfg.Server, grpc.WithTransportCredentials(credentials.NewTLS(
		tlsconf.Client(cfg.ServerName(), cfg.RootCA(), id.Cert, id.Chain, id.Key))))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	stream, err := openrmmv1.NewAgentServiceClient(conn).Connect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	stream.Send(&openrmmv1.AgentMessage{Msg: &openrmmv1.AgentMessage_Hello{Hello: &openrmmv1.Hello{Host: &openrmmv1.HostInfo{Hostname: "pc"}}}})
	if _, err := stream.Recv(); err != nil {
		t.Fatal(err)
	}
	if err := e.store.SetAgentStatus(context.Background(), e.tenant, id.AgentID, store.AgentRevoked); err != nil {
		t.Fatal(err)
	}
	stream.Send(&openrmmv1.AgentMessage{Msg: &openrmmv1.AgentMessage_Heartbeat{Heartbeat: &openrmmv1.Heartbeat{}}})
	if _, err := stream.Recv(); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("session of revoked agent: %v", err)
	}
}

// enrollOnly enrolls with the configured token and stores the identity.
func enrollOnly(t *testing.T, e *env, cfg *config.Config) *identity.Identity {
	t.Helper()
	key, _ := identity.NewKey()
	csr, _ := identity.CSR(key, "pc")
	resp, err := openrmmv1.NewEnrollmentServiceClient(dialNoCert(t, e)).Enroll(context.Background(),
		&openrmmv1.EnrollRequest{Token: cfg.EnrollToken, CsrDer: csr, Host: &openrmmv1.HostInfo{Hostname: "pc"}})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(resp.GetCertificateDer())
	if err != nil {
		t.Fatal(err)
	}
	chain, _ := x509.ParseCertificate(resp.GetChainDer()[0])
	return &identity.Identity{TenantID: resp.GetTenantId(), AgentID: resp.GetAgentId(), Key: key, Cert: cert, Chain: []*x509.Certificate{chain}}
}

func TestForeignCertificateIsRefused(t *testing.T) {
	e := start(t)
	// A certificate with a valid-looking identity from a different CA.
	otherRoot, _ := pki.NewRootCA("other", time.Now())
	otherCA, _ := pki.NewIntermediateCA(otherRoot, "other agents", time.Now())
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, _ := identity.CSR(key, "evil")
	cert, err := otherCA.IssueAgent(csr, pki.Identity{TenantID: e.tenant, AgentID: ids.NewUUID()}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg := tlsconf.Client("localhost", e.root.Cert, cert, []*x509.Certificate{otherCA.Cert}, key)
	conn, err := grpc.NewClient(e.addr, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	stream, err := openrmmv1.NewAgentServiceClient(conn).Connect(context.Background())
	if err == nil {
		_, err = stream.Recv()
	}
	if err == nil {
		t.Fatal("foreign certificate accepted")
	}
}

func TestAgentRejectsServerNotChainingToPinnedRoot(t *testing.T) {
	e := start(t)
	cfg := e.agentConfig(t, e.token(t, 1))
	otherRoot, _ := pki.NewRootCA("other", time.Now())
	// Pin a different root: the agent must refuse to talk to the gateway.
	rootFile := filepath.Join(t.TempDir(), "root.crt")
	os.WriteFile(rootFile, pki.EncodeCertPEM(otherRoot.Cert), 0o600)
	cfgFile := filepath.Join(t.TempDir(), "agent.json")
	os.WriteFile(cfgFile, []byte(`{"server":"`+e.addr+`","root_ca_file":"`+rootFile+`","enroll_token":"`+cfg.EnrollToken+`","data_dir":"`+cfg.DataDir+`",`+e.keysJSON()+`}`), 0o600)
	bad, err := config.Load(cfgFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := connectOnce(t, e, bad); err == nil {
		t.Fatal("agent trusted a server outside its pinned root")
	}
	agents, _ := e.store.ListAgents(context.Background(), e.tenant)
	if len(agents) != 0 {
		t.Fatal("token was sent to an untrusted server")
	}
}

// connectOnce runs the client until its first connection attempt fails, and
// returns that error.
func connectOnce(t *testing.T, e *env, cfg *config.Config) error {
	t.Helper()
	id, err := identity.Load(cfg.DataDir, cfg.RootCA())
	if err != nil {
		// Not enrolled: try to enroll against the server.
		conn, derr := grpc.NewClient(cfg.Server, grpc.WithTransportCredentials(credentials.NewTLS(
			tlsconf.Client(cfg.ServerName(), cfg.RootCA(), nil, nil, nil))))
		if derr != nil {
			return derr
		}
		defer conn.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := openrmmv1.NewEnrollmentServiceClient(conn).Enroll(ctx, enrollReq(t, cfg.EnrollToken))
		return err
	}
	conn, err := grpc.NewClient(cfg.Server, grpc.WithTransportCredentials(credentials.NewTLS(
		tlsconf.Client(cfg.ServerName(), cfg.RootCA(), id.Cert, id.Chain, id.Key))))
	if err != nil {
		return err
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := openrmmv1.NewAgentServiceClient(conn).Connect(ctx)
	if err != nil {
		return err
	}
	_, err = stream.Recv()
	return err
}

func dialNoCert(t *testing.T, e *env) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient(e.addr, grpc.WithTransportCredentials(credentials.NewTLS(
		tlsconf.Client("localhost", e.root.Cert, nil, nil, nil))))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func enrollReq(t *testing.T, token string) *openrmmv1.EnrollRequest {
	t.Helper()
	key, _ := identity.NewKey()
	csr, err := identity.CSR(key, "pc")
	if err != nil {
		t.Fatal(err)
	}
	return &openrmmv1.EnrollRequest{Token: token, CsrDer: csr, Host: &openrmmv1.HostInfo{Hostname: "pc"}}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	waitForWithin(t, cond, 5*time.Second)
}

func waitForWithin(t *testing.T, cond func() bool, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (e *env) onlyAgent(t *testing.T) store.Agent {
	t.Helper()
	agents, _ := e.store.ListAgents(context.Background(), e.tenant)
	if len(agents) != 1 {
		t.Fatalf("got %d agents", len(agents))
	}
	return agents[0]
}

// hello opens a session with id and returns the console's HelloAck.
func hello(t *testing.T, e *env, id *identity.Identity) (*openrmmv1.HelloAck, error) {
	t.Helper()
	conn, err := grpc.NewClient(e.addr, grpc.WithTransportCredentials(credentials.NewTLS(
		tlsconf.Client("localhost", e.root.Cert, id.Cert, id.Chain, id.Key))))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := openrmmv1.NewAgentServiceClient(conn).Connect(ctx)
	if err != nil {
		return nil, err
	}
	stream.Send(&openrmmv1.AgentMessage{Msg: &openrmmv1.AgentMessage_Hello{Hello: &openrmmv1.Hello{Host: &openrmmv1.HostInfo{Hostname: "pc"}}}})
	msg, err := stream.Recv()
	if err != nil {
		return nil, err
	}
	return msg.GetHelloAck(), nil
}

func TestNewAgentWaitsForApproval(t *testing.T) {
	e := start(t)
	cfg := e.agentConfig(t, e.token(t, 1))
	id := enrollOnly(t, e, cfg)
	if a := e.onlyAgent(t); a.Status != store.AgentPending || a.ApprovedAt != nil {
		t.Fatalf("new agent status = %s", a.Status)
	}
	// A pending agent may connect, and is told it is pending.
	ack, err := hello(t, e, id)
	if err != nil || !ack.GetApprovalPending() {
		t.Fatalf("pending hello: %v, %v", ack, err)
	}
	if err := e.store.ApproveAgent(context.Background(), e.tenant, id.AgentID, "tester", time.Now()); err != nil {
		t.Fatal(err)
	}
	ack, err = hello(t, e, id)
	if err != nil || ack.GetApprovalPending() {
		t.Fatalf("approved hello: %v, %v", ack, err)
	}
	if err := e.store.ApproveAgent(context.Background(), e.tenant, id.AgentID, "tester", time.Now()); err != store.ErrNotPending {
		t.Fatalf("double approval: %v", err)
	}
}

func TestAutoApproveToken(t *testing.T) {
	e := start(t)
	cfg := e.agentConfig(t, e.tokenWith(t, 1, true))
	id := enrollOnly(t, e, cfg)
	a := e.onlyAgent(t)
	if a.Status != store.AgentActive || a.ApprovedAt == nil || a.ApprovedBy == "" {
		t.Fatalf("auto-approved agent = %+v", a)
	}
	if ack, err := hello(t, e, id); err != nil || ack.GetApprovalPending() {
		t.Fatalf("hello: %v, %v", ack, err)
	}
}

func TestAgentRenewsCertificateAutomatically(t *testing.T) {
	e := start(t)
	// Enroll with the gateway clock 70 days back: the certificate has 20 of
	// its 90 days left, below the renewal threshold.
	e.offset.Store(int64(-70 * 24 * time.Hour))
	cfg := e.agentConfig(t, e.tokenWith(t, 1, true))
	old := enrollOnly(t, e, cfg)
	if err := identity.Save(cfg.DataDir, cfg.RootCA(), old); err != nil {
		t.Fatal(err)
	}
	e.offset.Store(0)

	runAgent(t, cfg)
	waitFor(t, func() bool {
		cur, err := identity.Load(cfg.DataDir, cfg.RootCA())
		return err == nil && !cur.Cert.Equal(old.Cert)
	})
	renewed, _ := identity.Load(cfg.DataDir, cfg.RootCA())
	if renewed.NeedsRenewal(time.Now()) || renewed.AgentID != old.AgentID {
		t.Fatalf("renewed identity = %s until %s", renewed.AgentID, renewed.Cert.NotAfter)
	}
	if renewed.Key.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(old.Key.Public()) {
		t.Fatal("renewal reused the old key")
	}
	// Once the agent has connected with the new certificate, the old one
	// is no longer accepted.
	waitFor(t, func() bool { return e.onlyAgent(t).PrevCertFingerprint == "" })
	if _, err := hello(t, e, old); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("old certificate after renewal: %v", err)
	}
	events, _ := e.store.ListAudit(context.Background(), e.tenant)
	if events[len(events)-1].Action != "agent.certificate_renewed" {
		t.Fatalf("last audit event = %s", events[len(events)-1].Action)
	}
}

func TestLostRenewalResponseDoesNotLockAgentOut(t *testing.T) {
	e := start(t)
	restore := gateway.SetMinRenewIntervalForTest(0)
	defer restore()
	cfg := e.agentConfig(t, e.tokenWith(t, 1, true))
	id := enrollOnly(t, e, cfg)
	conn, err := grpc.NewClient(e.addr, grpc.WithTransportCredentials(credentials.NewTLS(
		tlsconf.Client("localhost", e.root.Cert, id.Cert, id.Chain, id.Key))))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	key, _ := identity.NewKey()
	csr, _ := identity.CSR(key, "pc")
	// The console rotates the certificate, but the agent never sees the
	// response: it must still be able to connect with its old certificate.
	if _, err := openrmmv1.NewAgentServiceClient(conn).RenewCertificate(context.Background(),
		&openrmmv1.RenewCertificateRequest{CsrDer: csr}); err != nil {
		t.Fatal(err)
	}
	if _, err := hello(t, e, id); err != nil {
		t.Fatalf("old certificate refused after lost renewal: %v", err)
	}
	// And it can renew again with it.
	if _, err := openrmmv1.NewAgentServiceClient(conn).RenewCertificate(context.Background(),
		&openrmmv1.RenewCertificateRequest{CsrDer: csr}); err != nil {
		t.Fatalf("second renewal: %v", err)
	}
}

func TestRenewalRateLimited(t *testing.T) {
	e := start(t)
	cfg := e.agentConfig(t, e.tokenWith(t, 1, true))
	id := enrollOnly(t, e, cfg)
	conn, _ := grpc.NewClient(e.addr, grpc.WithTransportCredentials(credentials.NewTLS(
		tlsconf.Client("localhost", e.root.Cert, id.Cert, id.Chain, id.Key))))
	defer conn.Close()
	key, _ := identity.NewKey()
	csr, _ := identity.CSR(key, "pc")
	_, err := openrmmv1.NewAgentServiceClient(conn).RenewCertificate(context.Background(),
		&openrmmv1.RenewCertificateRequest{CsrDer: csr})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("renewal of a fresh certificate: %v", err)
	}
}
