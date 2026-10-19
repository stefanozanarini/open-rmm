// Package gateway implements the agent-facing gRPC endpoint of the console.
package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"sync"
	"time"
	"unicode/utf8"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/open-rmm/internal/console/audit"
	"github.com/stefanozanarini/open-rmm/internal/console/pkgfiles"
	"github.com/stefanozanarini/open-rmm/internal/console/relay"
	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/ids"
	"github.com/stefanozanarini/open-rmm/internal/pki"
)

const (
	maxMessageBytes = 4 << 20
	helloTimeout    = 15 * time.Second
)

// seenWriteInterval throttles last_seen updates and revocation checks
// triggered by heartbeats. A variable so tests can shorten it.
var seenWriteInterval = 5 * time.Minute

// Config configures a Server.
type Config struct {
	Store    store.Store
	AgentsCA *pki.CA
	Logger   *slog.Logger

	HeartbeatInterval time.Duration // default 60s
	// EnrollPerMinute and EnrollBurst bound enrollment attempts per source IP.
	EnrollPerMinute float64 // default 10
	EnrollBurst     int     // default 5

	// Packages is the package file store; empty Path: packages unavailable.
	Packages pkgfiles.Dir

	Now func() time.Time // for tests
}

// Server serves EnrollmentService and AgentService.
type Server struct {
	openrmmv1.UnimplementedEnrollmentServiceServer
	openrmmv1.UnimplementedAgentServiceServer

	store     store.Store
	ca        *pki.CA
	log       *slog.Logger
	heartbeat time.Duration
	enrollLim *ipLimiter
	now       func() time.Time
	// agentsPool verifies certificates forwarded by the gateway.
	agentsPool *x509.CertPool

	mu       sync.Mutex
	sessions map[string]*session // by tenant/agent
	packages pkgfiles.Dir
	shells   shellHub
}

type session struct {
	cancel context.CancelFunc
	wake   chan struct{}
}

// New returns a Server.
func New(cfg Config) (*Server, error) {
	if cfg.Store == nil || cfg.AgentsCA == nil {
		return nil, errors.New("gateway: store and agents CA are required")
	}
	s := &Server{
		store:     cfg.Store,
		ca:        cfg.AgentsCA,
		log:       cfg.Logger,
		heartbeat: cfg.HeartbeatInterval,
		now:       cfg.Now,
		sessions:  map[string]*session{},
		packages:  cfg.Packages,
	}
	if s.log == nil {
		s.log = slog.Default()
	}
	if s.heartbeat == 0 {
		s.heartbeat = 60 * time.Second
	}
	if s.heartbeat < time.Second || s.heartbeat > time.Hour {
		return nil, errors.New("gateway: heartbeat interval must be between 1s and 1h")
	}
	if s.now == nil {
		s.now = time.Now
	}
	perMin, burst := cfg.EnrollPerMinute, cfg.EnrollBurst
	if perMin == 0 {
		perMin = 10
	}
	if burst == 0 {
		burst = 5
	}
	s.enrollLim = newIPLimiter(perMin, burst)
	s.agentsPool = x509.NewCertPool()
	s.agentsPool.AddCert(cfg.AgentsCA.Cert)
	return s, nil
}

// TunnelGRPCServer builds the server the core runs on the tunnels it opens
// to the gateway. Transport security is provided by the tunnel itself (mTLS
// between core and gateway), and every call is marked as relayed so the
// agent identity is taken from the forwarded, re-verified certificate.
func (s *Server) TunnelGRPCServer() *grpc.Server {
	mark := func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		return handler(relay.MarkRelayed(ctx), req)
	}
	markStream := func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		return handler(srv, &wrappedStream{ServerStream: ss, ctx: relay.MarkRelayed(ss.Context())})
	}
	gs := grpc.NewServer(
		grpc.Creds(insecure.NewCredentials()), // #nosec G402 -- inside the core↔gateway mTLS tunnel
		grpc.MaxRecvMsgSize(maxMessageBytes),
		grpc.MaxSendMsgSize(maxMessageBytes),
		// One tunnel carries the streams of many agents.
		grpc.MaxConcurrentStreams(20000),
		grpc.ConnectionTimeout(30*time.Second),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 10 * time.Second, PermitWithoutStream: true}),
		grpc.KeepaliveParams(keepalive.ServerParameters{Time: time.Minute, Timeout: 20 * time.Second}),
		grpc.ChainUnaryInterceptor(mark, s.unaryAuth),
		grpc.ChainStreamInterceptor(markStream, s.streamAuth),
	)
	openrmmv1.RegisterEnrollmentServiceServer(gs, s)
	openrmmv1.RegisterAgentServiceServer(gs, s)
	return gs
}

// GRPCServer builds a gRPC server with TLS, limits and authentication.
func (s *Server) GRPCServer(tlsCfg *tls.Config) *grpc.Server {
	gs := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsCfg)),
		grpc.MaxRecvMsgSize(maxMessageBytes),
		grpc.MaxSendMsgSize(maxMessageBytes),
		grpc.MaxConcurrentStreams(16),
		grpc.ConnectionTimeout(10*time.Second),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 20 * time.Second, PermitWithoutStream: false}),
		grpc.KeepaliveParams(keepalive.ServerParameters{Time: 2 * time.Minute, Timeout: 20 * time.Second}),
		grpc.ChainUnaryInterceptor(s.unaryAuth),
		grpc.ChainStreamInterceptor(s.streamAuth),
	)
	openrmmv1.RegisterEnrollmentServiceServer(gs, s)
	openrmmv1.RegisterAgentServiceServer(gs, s)
	return gs
}

// Enroll exchanges an enrollment token and a CSR for an agent certificate.
func (s *Server) Enroll(ctx context.Context, req *openrmmv1.EnrollRequest) (*openrmmv1.EnrollResponse, error) {
	ip := peerIP(ctx)
	now := s.now()
	if !s.enrollLim.Allow(ip, now) {
		s.log.Warn("enrollment rate limited", "peer", ip.String())
		return nil, status.Error(codes.ResourceExhausted, "too many enrollment attempts")
	}
	if len(req.GetToken()) < 20 || len(req.GetToken()) > 200 {
		return nil, status.Error(codes.PermissionDenied, "invalid enrollment token")
	}
	host := hostFromProto(req.GetHost())
	if err := validateHost(host); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	tok, err := s.store.ConsumeEnrollmentToken(ctx, store.HashToken(req.GetToken()), now)
	if errors.Is(err, store.ErrTokenInvalid) {
		s.log.Warn("enrollment with invalid token", "peer", ip.String())
		return nil, status.Error(codes.PermissionDenied, "invalid enrollment token")
	}
	if err != nil {
		s.log.Error("consume enrollment token", "err", err)
		return nil, status.Error(codes.Unavailable, "temporarily unavailable")
	}
	id := pki.Identity{TenantID: tok.TenantID, AgentID: ids.NewUUID()}
	cert, err := s.ca.IssueAgent(req.GetCsrDer(), id, now)
	if errors.Is(err, pki.ErrBadCSR) {
		// The token slot is spent: a client that sends garbage must ask for
		// a new token rather than retry indefinitely.
		return nil, status.Error(codes.InvalidArgument, "invalid CSR")
	}
	if err != nil {
		s.log.Error("issue agent certificate", "err", err)
		return nil, status.Error(codes.Internal, "certificate issuance failed")
	}
	a := store.Agent{
		TenantID:        id.TenantID,
		ID:              id.AgentID,
		Status:          store.AgentPending,
		Host:            host,
		CertFingerprint: pki.Fingerprint(cert),
		CertNotAfter:    cert.NotAfter,
		EnrolledTokenID: tok.ID,
	}
	if tok.AutoApprove {
		a.Status, a.ApprovedAt, a.ApprovedBy = store.AgentActive, &now, "token:"+tok.ID
	}
	if err := s.store.CreateAgent(ctx, a); err != nil {
		s.log.Error("create agent", "err", err)
		return nil, status.Error(codes.Unavailable, "temporarily unavailable")
	}
	s.audit(ctx, id.TenantID, "agent:"+id.AgentID, "agent.enrolled", id.AgentID, map[string]any{
		"hostname": host.Hostname, "machine_id": host.MachineID, "token_id": tok.ID,
		"peer": ip.String(), "cert_fingerprint": a.CertFingerprint, "status": string(a.Status),
	})
	s.log.Info("agent enrolled", "tenant", id.TenantID, "agent", id.AgentID, "hostname", host.Hostname, "status", a.Status)
	return &openrmmv1.EnrollResponse{
		TenantId:       id.TenantID,
		AgentId:        id.AgentID,
		CertificateDer: cert.Raw,
		ChainDer:       [][]byte{s.ca.Cert.Raw},
	}, nil
}

// Connect is the agent's long-lived stream.
func (s *Server) Connect(stream openrmmv1.AgentService_ConnectServer) error {
	c, ok := callerFromContext(stream.Context())
	if !ok {
		return status.Error(codes.Unauthenticated, "unauthenticated")
	}
	a := c.agent
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()
	sess := s.replaceSession(a, cancel)
	defer s.dropSession(a, sess)

	hello, err := recvWithTimeout(ctx, stream, helloTimeout)
	if err != nil {
		return err
	}
	h := hello.GetHello()
	if h == nil {
		return status.Error(codes.InvalidArgument, "first message must be hello")
	}
	host := hostFromProto(h.GetHost())
	if err := validateHost(host); err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	ip := peerIP(ctx)
	ipp := &ip
	if !ip.IsValid() {
		ipp = nil
	}
	if err := s.store.UpdateAgentSeen(ctx, a.TenantID, a.ID, &host, s.now(), ipp); err != nil {
		s.log.Error("update agent", "err", err)
		return status.Error(codes.Unavailable, "temporarily unavailable")
	}
	if err := stream.Send(&openrmmv1.ConsoleMessage{Msg: &openrmmv1.ConsoleMessage_HelloAck{
		HelloAck: &openrmmv1.HelloAck{HeartbeatIntervalSeconds: int32(s.heartbeat / time.Second), ApprovalPending: a.Status == store.AgentPending}, // #nosec G115 -- bounded to [1, 3600] in New
	}}); err != nil {
		return err
	}
	s.log.Info("agent connected", "tenant", a.TenantID, "agent", a.ID, "hostname", host.Hostname,
		"peer", ip.String(), "status", a.Status)

	msgs := make(chan *openrmmv1.AgentMessage)
	recvErr := make(chan error, 1)
	go func() {
		for {
			m, err := stream.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			select {
			case msgs <- m:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Jobs already sent in this session are not sent again on every wake-up;
	// unanswered ones are re-sent once per session (the agent deduplicates).
	sent := map[string]bool{}
	offered := map[string]bool{}
	var policyHash []byte
	if a.Status == store.AgentActive {
		if err := s.sendPolicies(ctx, stream, a, &policyHash); err != nil {
			return err
		}
		if err := s.dispatch(ctx, stream, a, sent); err != nil {
			return err
		}
		if err := s.offerUpdate(ctx, stream, a, offered); err != nil {
			return err
		}
	}
	lastWrite := s.now()
	// An agent silent for three intervals is considered gone.
	idle := time.NewTimer(3 * s.heartbeat)
	defer idle.Stop()
	for {
		select {
		case <-ctx.Done():
			return status.Error(codes.Canceled, "session replaced or closed")
		case err := <-recvErr:
			if errors.Is(err, io.EOF) || status.Code(err) == codes.Canceled {
				s.log.Info("agent disconnected", "agent", a.ID)
				return nil
			}
			return err
		case <-idle.C:
			return status.Error(codes.DeadlineExceeded, "agent silent too long")
		case <-sess.wake:
			// Approval, ring or target may have changed: re-read the agent.
			cur, err := s.stillAuthorized(ctx, c)
			if err != nil {
				return err
			}
			cur.Host = a.Host
			a = cur
			if a.Status == store.AgentActive {
				if err := s.sendPolicies(ctx, stream, a, &policyHash); err != nil {
					return err
				}
				if err := s.dispatch(ctx, stream, a, sent); err != nil {
					return err
				}
				if err := s.offerUpdate(ctx, stream, a, offered); err != nil {
					return err
				}
			}
		case msg := <-msgs:
			idle.Reset(3 * s.heartbeat)
			switch m := msg.GetMsg().(type) {
			case *openrmmv1.AgentMessage_Heartbeat:
				if now := s.now(); now.Sub(lastWrite) >= seenWriteInterval {
					// Revocation must also end sessions that are already open.
					cur, err := s.stillAuthorized(ctx, c)
					if err != nil {
						return err
					}
					a = cur
					if err := s.store.UpdateAgentSeen(ctx, a.TenantID, a.ID, nil, now, ipp); err != nil {
						s.log.Error("update agent", "err", err)
					}
					lastWrite = now
				}
				// Fallback in case a notification was missed.
				if a.Status == store.AgentActive {
					if err := s.dispatch(ctx, stream, a, sent); err != nil {
						return err
					}
				}
			case *openrmmv1.AgentMessage_PolicyResult:
				if s.recordPolicyResult(ctx, a, m.PolicyResult) {
					if err := stream.Send(&openrmmv1.ConsoleMessage{Msg: &openrmmv1.ConsoleMessage_JobUpdateAck{
						JobUpdateAck: &openrmmv1.JobUpdateAck{JobId: m.PolicyResult.GetRunId()},
					}}); err != nil {
						return err
					}
				}
			case *openrmmv1.AgentMessage_UpdateStatus:
				s.recordUpdateStatus(ctx, a, m.UpdateStatus)
			case *openrmmv1.AgentMessage_JobUpdate:
				if ack := s.recordJobUpdate(ctx, a, m.JobUpdate); ack {
					if err := stream.Send(&openrmmv1.ConsoleMessage{Msg: &openrmmv1.ConsoleMessage_JobUpdateAck{
						JobUpdateAck: &openrmmv1.JobUpdateAck{JobId: m.JobUpdate.GetJobId()},
					}}); err != nil {
						return err
					}
				}
			default:
				return status.Error(codes.InvalidArgument, "unexpected message")
			}
		}
	}
}

// stillAuthorized re-reads the agent during a session. It ends the session if
// the agent was revoked or the session's certificate was superseded, and
// returns the current record (e.g. pending → active after approval).
func (s *Server) stillAuthorized(ctx context.Context, c caller) (store.Agent, error) {
	cur, err := s.store.GetAgent(ctx, c.agent.TenantID, c.agent.ID)
	if err != nil {
		s.log.Error("agent lookup failed", "err", err)
		return c.agent, nil // keep the session; the next check will retry
	}
	if cur.Status == store.AgentRevoked {
		s.log.Warn("closing session of revoked agent", "agent", cur.ID)
		return cur, status.Error(codes.PermissionDenied, "agent revoked")
	}
	if c.fingerprint != cur.CertFingerprint && c.fingerprint != cur.PrevCertFingerprint {
		return cur, status.Error(codes.PermissionDenied, "certificate superseded")
	}
	return cur, nil
}

// minRenewInterval rejects renewals of a certificate younger than this, so a
// compromised or buggy agent cannot mint certificates in a loop.
var minRenewInterval = time.Hour

// RenewCertificate issues a new certificate for the calling agent.
func (s *Server) RenewCertificate(ctx context.Context, req *openrmmv1.RenewCertificateRequest) (*openrmmv1.RenewCertificateResponse, error) {
	c, ok := callerFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "unauthenticated")
	}
	now := s.now()
	if now.Sub(c.leaf.NotBefore) < minRenewInterval {
		return nil, status.Error(codes.FailedPrecondition, "certificate too recent to renew")
	}
	id := pki.Identity{TenantID: c.agent.TenantID, AgentID: c.agent.ID}
	cert, err := s.ca.IssueAgent(req.GetCsrDer(), id, now)
	if errors.Is(err, pki.ErrBadCSR) {
		return nil, status.Error(codes.InvalidArgument, "invalid CSR")
	}
	if err != nil {
		s.log.Error("issue agent certificate", "err", err)
		return nil, status.Error(codes.Internal, "certificate issuance failed")
	}
	newFP := pki.Fingerprint(cert)
	err = s.store.RotateAgentCert(ctx, id.TenantID, id.AgentID, c.fingerprint, newFP, cert.NotAfter)
	if errors.Is(err, store.ErrCertMismatch) {
		return nil, status.Error(codes.PermissionDenied, "certificate superseded")
	}
	if err != nil {
		s.log.Error("rotate agent certificate", "err", err)
		return nil, status.Error(codes.Unavailable, "temporarily unavailable")
	}
	s.audit(ctx, id.TenantID, "agent:"+id.AgentID, "agent.certificate_renewed", id.AgentID, map[string]any{
		"old_fingerprint": c.fingerprint, "new_fingerprint": newFP,
		"not_after": cert.NotAfter.UTC().Format(time.RFC3339),
	})
	s.log.Info("agent certificate renewed", "agent", id.AgentID, "not_after", cert.NotAfter)
	return &openrmmv1.RenewCertificateResponse{CertificateDer: cert.Raw, ChainDer: [][]byte{s.ca.Cert.Raw}}, nil
}

// replaceSession makes sure an agent has at most one live stream: a new
// connection closes the previous one.
func (s *Server) replaceSession(a store.Agent, cancel context.CancelFunc) *session {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := a.TenantID + "/" + a.ID
	if old, ok := s.sessions[k]; ok {
		old.cancel()
	}
	sess := &session{cancel: cancel, wake: make(chan struct{}, 1)}
	s.sessions[k] = sess
	return sess
}

func (s *Server) dropSession(a store.Agent, sess *session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := a.TenantID + "/" + a.ID
	// Only remove our own entry; a newer session may have replaced it.
	if s.sessions[k] == sess {
		delete(s.sessions, k)
	}
}

// ConnectedAgents returns the number of live sessions.
func (s *Server) ConnectedAgents() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

func recvWithTimeout(ctx context.Context, stream openrmmv1.AgentService_ConnectServer, d time.Duration) (*openrmmv1.AgentMessage, error) {
	type result struct {
		msg *openrmmv1.AgentMessage
		err error
	}
	ch := make(chan result, 1)
	go func() {
		m, err := stream.Recv()
		ch <- result{m, err}
	}()
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case r := <-ch:
		return r.msg, r.err
	case <-t.C:
		return nil, status.Error(codes.DeadlineExceeded, "agent silent too long")
	case <-ctx.Done():
		return nil, status.Error(codes.Canceled, "session replaced or closed")
	}
}

func (s *Server) audit(ctx context.Context, tenantID, actor, action, target string, details map[string]any) {
	if _, err := s.store.AppendAudit(ctx, audit.Event{
		TenantID: tenantID, OccurredAt: s.now(), Actor: actor, Action: action, Target: target, Details: details,
	}); err != nil {
		s.log.Error("audit append failed", "action", action, "err", err)
	}
}

func hostFromProto(h *openrmmv1.HostInfo) store.HostInfo {
	return store.HostInfo{
		Hostname:     h.GetHostname(),
		OS:           h.GetOs(),
		OSVersion:    h.GetOsVersion(),
		Arch:         h.GetArch(),
		AgentVersion: h.GetAgentVersion(),
		MachineID:    h.GetMachineId(),
		OSFamily:     normalizeFamily(h.GetOsFamily()),
	}
}

func validateHost(h store.HostInfo) error {
	for _, f := range []string{h.Hostname, h.OS, h.OSVersion, h.Arch, h.AgentVersion, h.MachineID} {
		if len(f) > 256 || !utf8.ValidString(f) {
			return errors.New("host info field too long or not UTF-8")
		}
	}
	if h.Hostname == "" {
		return errors.New("hostname is required")
	}
	return nil
}

func normalizeFamily(f string) string {
	switch f {
	case "client", "server":
		return f
	}
	return "unknown"
}
