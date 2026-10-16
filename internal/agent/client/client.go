// Package client keeps the agent connected to the console: it enrolls when
// needed, then maintains the Connect stream with heartbeats, reconnecting
// with exponential backoff and jitter.
package client

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/open-rmm/internal/agent/config"
	"github.com/stefanozanarini/open-rmm/internal/agent/hostinfo"
	"github.com/stefanozanarini/open-rmm/internal/agent/identity"
	"github.com/stefanozanarini/open-rmm/internal/agent/jobs"
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

// Client runs the agent's connection loop.
type Client struct {
	cfg     *config.Config
	version string
	log     *slog.Logger

	// OnConnected, if set, is called after each successful hello (tests).
	OnConnected func()
}

// New returns a Client.
func New(cfg *config.Config, version string, log *slog.Logger) *Client {
	if log == nil {
		log = slog.Default()
	}
	return &Client{cfg: cfg, version: version, log: log}
}

// Run blocks until ctx is cancelled.
func (c *Client) Run(ctx context.Context) error {
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
		switch status.Code(err) {
		case codes.PermissionDenied, codes.Unauthenticated:
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
	if errors.Is(err, identity.ErrNoIdentity) {
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
	return id, nil
}

func (c *Client) connect(ctx context.Context, id *identity.Identity) (bool, error) {
	verifier, err := jobs.NewVerifier(c.cfg.JobKeyring(), id.TenantID, id.AgentID, c.cfg.DataDir)
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
	c.log.Info("connected", "server", c.cfg.Server, "heartbeat", interval)
	if c.OnConnected != nil {
		c.OnConnected()
	}

	sendCh := make(chan *openrmmv1.AgentMessage, 16)
	recvErr := make(chan error, 1)
	go func() {
		for {
			msg, err := stream.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			if env := msg.GetJob(); env != nil {
				select {
				case sendCh <- c.handleJob(verifier, env):
				case <-sctx.Done():
					return
				}
			}
		}
	}()

	tick := time.NewTicker(interval)
	defer tick.Stop()
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
		}
	}
}

// handleJob verifies a job. Execution through modules is the next phase-0
// step; until then verified jobs are rejected as unsupported.
func (c *Client) handleJob(v *jobs.Verifier, env *openrmmv1.SignedEnvelope) *openrmmv1.AgentMessage {
	upd := &openrmmv1.JobUpdate{State: openrmmv1.JobUpdate_STATE_REJECTED}
	job, err := v.Verify(env, time.Now())
	if err != nil {
		c.log.Warn("job rejected", "err", err)
		upd.Error = "verification failed"
	} else {
		upd.JobId = job.GetJobId()
		upd.Error = "module runtime not available"
		c.log.Info("job verified but not executed", "job", job.GetJobId(), "module", job.GetModule())
	}
	return &openrmmv1.AgentMessage{Msg: &openrmmv1.AgentMessage_JobUpdate{JobUpdate: upd}}
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
