// Package client keeps the agent connected to the console: it enrolls when
// needed, then maintains the Connect stream with heartbeats, reconnecting
// with exponential backoff and jitter.
package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/open-rmm/internal/agent/config"
	"github.com/stefanozanarini/open-rmm/internal/agent/executor"
	"github.com/stefanozanarini/open-rmm/internal/agent/health"
	"github.com/stefanozanarini/open-rmm/internal/agent/hostinfo"
	"github.com/stefanozanarini/open-rmm/internal/agent/identity"
	"github.com/stefanozanarini/open-rmm/internal/agent/jobs"
	"github.com/stefanozanarini/open-rmm/internal/agent/modcache"
	"github.com/stefanozanarini/open-rmm/internal/agent/policies"
	"github.com/stefanozanarini/open-rmm/internal/agent/secfile"
	"github.com/stefanozanarini/open-rmm/internal/agent/svcctl"
	"github.com/stefanozanarini/open-rmm/internal/agent/updater"
	"github.com/stefanozanarini/open-rmm/internal/modules"
	"github.com/stefanozanarini/open-rmm/internal/release"
	"github.com/stefanozanarini/open-rmm/internal/tlsconf"
)

const (
	minBackoff = 2 * time.Second
	maxBackoff = 5 * time.Minute
	// deniedBackoff is used when the console rejects us outright (revoked,
	// bad token): retrying fast would only produce noise.
	deniedBackoff = 30 * time.Minute
	rpcTimeout    = 30 * time.Second
)

// errRenewed ends a session after a certificate renewal so the agent
// reconnects at once with the new certificate.
var errRenewed = errors.New("certificate renewed, reconnecting")

// Client runs the agent's connection loop.
type Client struct {
	cfg     *config.Config
	version string
	log     *slog.Logger

	// OnConnected, if set, is called after each successful hello (tests).
	OnConnected func()
	// ConfigPath is passed to the watchdog service when the agent updates
	// it; empty disables watchdog updates (development runs).
	ConfigPath string
	// Services controls the OS services (nil: no watchdog updates).
	Services svcctl.Manager

	updater   *updater.Updater
	connected atomic.Bool
	lastConn  atomic.Int64

	runCtx    context.Context
	mu        sync.Mutex
	exec      *executor.Executor
	policies  *policies.Manager
	execAgent string
}

// New returns a Client.
func New(cfg *config.Config, version string, log *slog.Logger) *Client {
	if log == nil {
		log = slog.Default()
	}
	return &Client{cfg: cfg, version: version, log: log, updater: updater.New(cfg, version, log)}
}

// writeHealth refreshes the health file read by the watchdog until ctx ends.
func (c *Client) writeHealth(ctx context.Context) {
	exe, _ := os.Executable()
	h := health.Health{Version: c.version, PID: os.Getpid(), Executable: exe, Started: time.Now()}
	t := time.NewTicker(health.Interval)
	defer t.Stop()
	for {
		h.Updated, h.Connected = time.Now(), c.connected.Load()
		if lc := c.lastConn.Load(); lc > 0 {
			h.LastConnected = time.Unix(lc, 0)
		}
		if err := health.Write(c.cfg.DataDir, h); err != nil {
			c.log.Warn("health file", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Run blocks until ctx is cancelled.
func (c *Client) Run(ctx context.Context) error {
	c.runCtx = ctx
	if err := secfile.EnsureDir(c.cfg.DataDir); err != nil {
		return err
	}
	go c.writeHealth(ctx)
	defer func() {
		c.mu.Lock()
		e := c.exec
		c.mu.Unlock()
		if e != nil {
			e.Wait()
		}
	}()
	backoff := minBackoff
	for {
		connected, err := c.runOnce(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if connected {
			backoff = minBackoff
		}
		wait := jitter(backoff)
		switch {
		case errors.Is(err, errRenewed):
			wait = 0
		case status.Code(err) == codes.PermissionDenied, status.Code(err) == codes.Unauthenticated:
			wait = jitter(deniedBackoff)
		}
		c.log.Warn("connection ended, retrying", "err", err, "in", wait.Round(time.Second))
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
		if !connected {
			backoff = min(backoff*2, maxBackoff)
		}
	}
}

// jitter returns a random duration in [d/2, d] ("equal jitter").
func jitter(d time.Duration) time.Duration {
	half := d / 2
	return half + rand.N(half+1)
}

func (c *Client) runOnce(ctx context.Context) (connected bool, err error) {
	id, err := identity.Load(c.cfg.DataDir, c.cfg.RootCA())
	switch {
	case errors.Is(err, identity.ErrNoIdentity):
		id, err = c.enroll(ctx)
	case errors.Is(err, identity.ErrExpired):
		// Offline longer than the certificate lifetime: only a new
		// enrollment (and a new agent record) can bring it back.
		c.log.Error("certificate expired, enrolling again", "err", err)
		id, err = c.enroll(ctx)
	}
	if err != nil {
		return false, err
	}
	return c.connect(ctx, id)
}

func (c *Client) dial(id *identity.Identity) (*grpc.ClientConn, error) {
	var tlsCfg = tlsconf.Client(c.cfg.ServerName(), c.cfg.RootCA(), nil, nil, nil)
	if id != nil {
		tlsCfg = tlsconf.Client(c.cfg.ServerName(), c.cfg.RootCA(), id.Cert, id.Chain, id.Key)
	}
	return grpc.NewClient("dns:///"+c.cfg.Server,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 2 * time.Minute, Timeout: 20 * time.Second}),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(4<<20)),
	)
}

func (c *Client) enroll(ctx context.Context) (*identity.Identity, error) {
	if c.cfg.EnrollToken == "" {
		return nil, status.Error(codes.Unauthenticated, "not enrolled and no enrollment token configured")
	}
	host := hostinfo.Collect(c.version)
	key, err := identity.NewKey()
	if err != nil {
		return nil, err
	}
	csr, err := identity.CSR(key, host.GetHostname())
	if err != nil {
		return nil, err
	}
	conn, err := c.dial(nil)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	rctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()
	resp, err := openrmmv1.NewEnrollmentServiceClient(conn).Enroll(rctx, &openrmmv1.EnrollRequest{
		Token: c.cfg.EnrollToken, CsrDer: csr, Host: host,
	})
	if err != nil {
		return nil, fmt.Errorf("enroll: %w", err)
	}
	certs, err := parseDER(append([][]byte{resp.GetCertificateDer()}, resp.GetChainDer()...))
	if err != nil {
		return nil, err
	}
	id := &identity.Identity{
		TenantID: resp.GetTenantId(), AgentID: resp.GetAgentId(),
		Key: key, Cert: certs[0], Chain: certs[1:],
	}
	if err := identity.Save(c.cfg.DataDir, c.cfg.RootCA(), id); err != nil {
		return nil, err
	}
	c.log.Info("enrolled", "tenant", id.TenantID, "agent", id.AgentID)
	if err := config.ForgetEnrollToken(); err != nil {
		c.log.Warn("could not remove the enrollment token from the registry", "err", err)
	}
	return id, nil
}

func (c *Client) connect(ctx context.Context, id *identity.Identity) (bool, error) {
	verifier, err := jobs.NewVerifier(c.cfg.JobKeyring(), id.TenantID, id.AgentID, c.cfg.DataDir)
	if err != nil {
		return false, err
	}
	exec, pols, err := c.executorFor(id)
	if err != nil {
		return false, err
	}
	conn, err := c.dial(id)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := openrmmv1.NewAgentServiceClient(conn).Connect(sctx)
	if err != nil {
		return false, err
	}
	if err := stream.Send(&openrmmv1.AgentMessage{Msg: &openrmmv1.AgentMessage_Hello{
		Hello: &openrmmv1.Hello{Host: hostinfo.Collect(c.version)},
	}}); err != nil {
		return false, err
	}
	first, err := stream.Recv()
	if err != nil {
		return false, err
	}
	ack := first.GetHelloAck()
	if ack == nil {
		return false, errors.New("console did not acknowledge hello")
	}
	interval := time.Duration(ack.GetHeartbeatIntervalSeconds()) * time.Second
	if interval < 10*time.Second || interval > 10*time.Minute {
		interval = 60 * time.Second
	}
	if ack.GetApprovalPending() {
		c.log.Warn("connected, waiting for an operator to approve this agent", "agent", id.AgentID)
	} else {
		c.log.Info("connected", "server", c.cfg.Server, "heartbeat", interval)
	}
	if c.OnConnected != nil {
		c.OnConnected()
	}
	c.connected.Store(true)
	c.lastConn.Store(time.Now().Unix())
	defer c.connected.Store(false)
	if id.NeedsRenewal(time.Now()) {
		if err := c.renew(ctx, conn, id); err != nil {
			c.log.Error("certificate renewal failed, will retry", "err", err)
		} else {
			return true, errRenewed
		}
	}

	sendCh := make(chan *openrmmv1.AgentMessage, 64)
	sess := &session{ctx: sctx, out: sendCh, conn: conn}
	go c.updater.ReportResult(sess)
	if c.Services != nil && c.ConfigPath != "" {
		args := []string{"run", "-config", c.ConfigPath}
		if runtime.GOOS == "windows" {
			args = []string{"run", "-service", "-config", c.ConfigPath}
		}
		go updater.UpdateWatchdog(c.Services, c.cfg.InstallDir, args, c.log)
	}
	recvErr := make(chan error, 1)
	go func() {
		for {
			msg, err := stream.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			switch m := msg.GetMsg().(type) {
			case *openrmmv1.ConsoleMessage_Job:
				c.handleJob(verifier, exec, m.Job)
			case *openrmmv1.ConsoleMessage_JobUpdateAck:
				exec.Acked(m.JobUpdateAck.GetJobId())
			case *openrmmv1.ConsoleMessage_AgentUpdate:
				c.updater.Offer(sctx, sess, m.AgentUpdate.GetManifest())
			case *openrmmv1.ConsoleMessage_PolicySet:
				pols.Apply(m.PolicySet)
			}
		}
	}()
	// Attach after the receive loop is running: it resends the outbox
	// through sendCh, which the loop below drains.
	go exec.Attach(sess)
	defer exec.Detach(sess)

	tick := time.NewTicker(interval)
	defer tick.Stop()
	lastRenewAttempt := time.Now()
	for {
		select {
		case <-ctx.Done():
			stream.CloseSend()
			return true, nil
		case err := <-recvErr:
			return true, err
		case m := <-sendCh:
			if err := stream.Send(m); err != nil {
				return true, err
			}
		case <-tick.C:
			if err := stream.Send(&openrmmv1.AgentMessage{Msg: &openrmmv1.AgentMessage_Heartbeat{
				Heartbeat: &openrmmv1.Heartbeat{SentAtUnixMs: time.Now().UnixMilli()},
			}}); err != nil {
				return true, err
			}
			if id.NeedsRenewal(time.Now()) && time.Since(lastRenewAttempt) > time.Hour {
				lastRenewAttempt = time.Now()
				if err := c.renew(ctx, conn, id); err != nil {
					c.log.Error("certificate renewal failed, will retry", "err", err)
				} else {
					stream.CloseSend()
					return true, errRenewed
				}
			}
		}
	}
}

// executorFor returns the executor and policy manager of the current
// identity. Jobs and policies keep running across reconnections (policies
// also offline); a new identity (re-enrollment) gets new ones.
func (c *Client) executorFor(id *identity.Identity) (*executor.Executor, *policies.Manager, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.exec != nil && c.execAgent == id.AgentID {
		return c.exec, c.policies, nil
	}
	e, err := executor.New(c.runCtx, c.cfg, id.TenantID, id.AgentID, c.log)
	if err != nil {
		return nil, nil, err
	}
	pm, err := policies.New(c.cfg.JobKeyring(), id.TenantID, c.cfg.DataDir, policies.SystemProbe{}, e, c.log)
	if err != nil {
		return nil, nil, err
	}
	go pm.Run(c.runCtx)
	c.exec, c.policies, c.execAgent = e, pm, id.AgentID
	return e, pm, nil
}

// renew obtains a certificate for a fresh key pair and stores it. The old
// identity remains on disk until the new one is fully written.
func (c *Client) renew(ctx context.Context, conn *grpc.ClientConn, id *identity.Identity) error {
	key, err := identity.NewKey()
	if err != nil {
		return err
	}
	csr, err := identity.CSR(key, id.AgentID)
	if err != nil {
		return err
	}
	rctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()
	resp, err := openrmmv1.NewAgentServiceClient(conn).RenewCertificate(rctx, &openrmmv1.RenewCertificateRequest{CsrDer: csr})
	if err != nil {
		return err
	}
	certs, err := parseDER(append([][]byte{resp.GetCertificateDer()}, resp.GetChainDer()...))
	if err != nil {
		return err
	}
	next := &identity.Identity{TenantID: id.TenantID, AgentID: id.AgentID, Key: key, Cert: certs[0], Chain: certs[1:]}
	if err := identity.Save(c.cfg.DataDir, c.cfg.RootCA(), next); err != nil {
		return err
	}
	c.log.Info("certificate renewed", "not_after", next.Cert.NotAfter)
	return nil
}

// handleJob verifies a job and hands it to the executor. Envelopes that fail
// verification are dropped: nothing in them can be trusted, not even the job
// id to report on.
func (c *Client) handleJob(v *jobs.Verifier, exec *executor.Executor, env *openrmmv1.SignedEnvelope) {
	job, err := v.Verify(env, time.Now())
	switch {
	case errors.Is(err, jobs.ErrReplay):
		exec.Replayed(job.GetJobId())
	case err != nil:
		c.log.Warn("job rejected: verification failed", "err", err)
	default:
		exec.Start(job)
	}
}

// session is the executor's view of the live connection.
type session struct {
	ctx  context.Context
	out  chan<- *openrmmv1.AgentMessage
	conn *grpc.ClientConn
}

func (s *session) Send(m *openrmmv1.AgentMessage) {
	select {
	case s.out <- m:
	case <-s.ctx.Done():
	}
}

func (s *session) SendUpdateStatus(u *openrmmv1.UpdateStatus) {
	select {
	case s.out <- &openrmmv1.AgentMessage{Msg: &openrmmv1.AgentMessage_UpdateStatus{UpdateStatus: u}}:
	case <-s.ctx.Done():
	}
}

// OpenShell opens the stream of an interactive shell session.
func (s *session) OpenShell(ctx context.Context) (executor.ShellStream, error) {
	return openrmmv1.NewAgentServiceClient(s.conn).Shell(ctx)
}

// FetchRelease downloads the executables of a release.
func (s *session) FetchRelease(ctx context.Context, version, platform string) (map[string][]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	stream, err := openrmmv1.NewAgentServiceClient(s.conn).GetAgentRelease(ctx,
		&openrmmv1.GetAgentReleaseRequest{Version: version, Platform: platform})
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{}
	total := 0
	for {
		chunk, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return files, nil
		}
		if err != nil {
			return nil, err
		}
		total += len(chunk.GetData())
		if total > 3*release.MaxFileSize || len(files) > 4 {
			return nil, errors.New("release too large")
		}
		files[chunk.GetFile()] = append(files[chunk.GetFile()], chunk.GetData()...)
	}
}

// FetchPackage downloads a package to dest, checking size and SHA-256; a
// partial or wrong file is removed.
func (s *session) FetchPackage(ctx context.Context, jobID string, ref *openrmmv1.PackageRef, dest string) (err error) {
	// At least 1 MB/s, never less than 15 minutes.
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute+time.Duration(ref.GetSize()/(1<<20))*time.Second)
	defer cancel()
	stream, err := openrmmv1.NewAgentServiceClient(s.conn).GetPackage(ctx, &openrmmv1.GetPackageRequest{JobId: jobID, Sha256: ref.GetSha256()})
	if err != nil {
		return err
	}
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304 -- validated file name in the job work directory
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			_ = os.Remove(dest)
		}
	}()
	h := sha256.New()
	var n int64
	idle := idleCancel(cancel)
	defer idle.stop()
	for {
		chunk, rerr := stream.Recv()
		idle.touch()
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			return rerr
		}
		n += int64(len(chunk.GetData()))
		if n > ref.GetSize() {
			return errors.New("package larger than announced")
		}
		h.Write(chunk.GetData())
		if _, err := f.Write(chunk.GetData()); err != nil {
			return err
		}
	}
	if n != ref.GetSize() || !bytes.Equal(h.Sum(nil), ref.GetSha256()) {
		return errors.New("package size or SHA-256 mismatch")
	}
	return nil
}

// FetchModule downloads a module over the authenticated connection.
func (s *session) FetchModule(ctx context.Context, id, version string) (*modcache.Fetched, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	stream, err := openrmmv1.NewAgentServiceClient(s.conn).GetModule(ctx, &openrmmv1.GetModuleRequest{Module: id, Version: version})
	if err != nil {
		return nil, err
	}
	var f *modcache.Fetched
	var archive []byte
	idle := idleCancel(cancel)
	defer idle.stop()
	for {
		chunk, err := stream.Recv()
		idle.touch()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if f == nil {
			m := chunk.GetManifest()
			if m == nil {
				return nil, errors.New("first module chunk carries no manifest")
			}
			f = &modcache.Fetched{KeyID: m.GetKeyId(), Manifest: m.GetPayload(), Signature: m.GetSignature()}
		}
		if len(archive)+len(chunk.GetData()) > modules.MaxArchiveSize {
			return nil, errors.New("module archive too large")
		}
		archive = append(archive, chunk.GetData()...)
	}
	if f == nil {
		return nil, errors.New("empty module stream")
	}
	f.Archive = archive
	return f, nil
}

func parseDER(ders [][]byte) ([]*x509.Certificate, error) {
	out := make([]*x509.Certificate, 0, len(ders))
	for _, d := range ders {
		c, err := x509.ParseCertificate(d)
		if err != nil {
			return nil, fmt.Errorf("issued certificate: %w", err)
		}
		out = append(out, c)
	}
	return out, nil
}

// downloadIdle bounds the silence of a download stream: over the DMZ relay
// a console restart can leave a stream open with nothing coming, and the
// job would wait for the whole download timeout.
const downloadIdle = 2 * time.Minute

type idleTimer struct{ t *time.Timer }

// idleCancel cancels a download that receives nothing for downloadIdle.
func idleCancel(cancel context.CancelFunc) *idleTimer {
	return &idleTimer{t: time.AfterFunc(downloadIdle, cancel)}
}

func (i *idleTimer) touch() { i.t.Reset(downloadIdle) }
func (i *idleTimer) stop()  { i.t.Stop() }
