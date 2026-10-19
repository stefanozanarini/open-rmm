package gateway

import (
	"context"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/ids"
	"github.com/stefanozanarini/open-rmm/internal/modules"
)

// shellWait is how long the console waits for the agent to open a session
// it has just approved.
const shellWait = 90 * time.Second

// shellSession joins an agent's Shell stream and the console attached to it.
type shellSession struct {
	tenant    string
	fromAgent chan *openrmmv1.ShellFrame
	toAgent   chan *openrmmv1.ShellFrame
	done      chan struct{}
	mu        sync.Mutex
	attached  bool
}

// shellHub holds the open sessions, by job id.
type shellHub struct {
	mu       sync.Mutex
	sessions map[string]*shellSession
	opened   chan struct{} // closed and replaced when a session opens
}

func (h *shellHub) init() {
	if h.sessions == nil {
		h.sessions, h.opened = map[string]*shellSession{}, make(chan struct{})
	}
}

func (h *shellHub) add(tenant, job string) (*shellSession, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.init()
	if _, ok := h.sessions[job]; ok {
		return nil, false
	}
	s := &shellSession{tenant: tenant, fromAgent: make(chan *openrmmv1.ShellFrame, 1024),
		toAgent: make(chan *openrmmv1.ShellFrame, 256), done: make(chan struct{})}
	h.sessions[job] = s
	close(h.opened)
	h.opened = make(chan struct{})
	return s, true
}

func (h *shellHub) remove(job string, s *shellSession) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.sessions[job] == s {
		delete(h.sessions, job)
	}
	close(s.done)
}

// wait returns the session of job, waiting for the agent to open it.
func (h *shellHub) wait(ctx context.Context, job string) *shellSession {
	for {
		h.mu.Lock()
		h.init()
		s, opened := h.sessions[job], h.opened
		h.mu.Unlock()
		if s != nil {
			return s
		}
		select {
		case <-opened:
		case <-ctx.Done():
			return nil
		}
	}
}

// Shell is the agent side of an interactive session: allowed only for an
// unfinished job of this agent whose module has the interactive_shell
// capability.
func (s *Server) Shell(stream openrmmv1.AgentService_ShellServer) error {
	ctx := stream.Context()
	c, ok := callerFromContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "unauthenticated")
	}
	if c.agent.Status != store.AgentActive {
		return status.Error(codes.PermissionDenied, "agent not approved")
	}
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	jobID := first.GetJobId()
	if !ids.IsUUID(jobID) {
		return status.Error(codes.InvalidArgument, "invalid job id")
	}
	j, err := s.store.GetJob(ctx, c.agent.TenantID, jobID)
	if err != nil || j.AgentID != c.agent.ID || j.State.Final() || s.now().After(j.ExpiresAt.Add(shellMaxAge)) {
		s.log.Warn("shell refused", "agent", c.agent.ID, "job", jobID)
		return status.Error(codes.PermissionDenied, "no pending shell job for this agent")
	}
	if !s.isShellModule(ctx, j) {
		return status.Error(codes.PermissionDenied, "the job is not an interactive shell")
	}
	sess, ok := s.shells.add(c.agent.TenantID, jobID)
	if !ok {
		return status.Error(codes.AlreadyExists, "session already open")
	}
	defer s.shells.remove(jobID, sess)
	s.log.Info("shell session open", "agent", c.agent.ID, "job", jobID)
	errc := make(chan error, 1)
	go func() {
		for {
			f, err := stream.Recv()
			if err != nil {
				errc <- nil
				return
			}
			select {
			case sess.fromAgent <- f:
			default: // nobody attached and the buffer is full: drop
			}
			if f.GetClose() {
				errc <- nil
				return
			}
		}
	}()
	for {
		select {
		case f := <-sess.toAgent:
			if err := stream.Send(f); err != nil {
				return err
			}
		case err := <-errc:
			s.log.Info("shell session closed", "agent", c.agent.ID, "job", jobID)
			return err
		case <-ctx.Done():
			return nil
		}
	}
}

// shellMaxAge bounds how long after its pickup deadline a shell job can
// still open its stream.
const shellMaxAge = time.Hour

func (s *Server) isShellModule(ctx context.Context, j store.Job) bool {
	mod, err := s.store.GetModule(ctx, j.Module, j.ModuleVersion)
	if err != nil {
		return false
	}
	man, err := modules.ParseManifest(mod.Manifest)
	return err == nil && man.HasCapability(modules.CapInteractiveShell)
}

// ShellBroker serves the web console's side of the sessions (Unix socket
// shared only with the web console).
type ShellBroker struct {
	openrmmv1.UnimplementedShellBrokerServiceServer
	s *Server
}

// Broker returns the broker of the server's sessions.
func (s *Server) Broker() *ShellBroker { return &ShellBroker{s: s} }

// Attach joins a session; the first frame names tenant and job.
func (b *ShellBroker) Attach(stream openrmmv1.ShellBrokerService_AttachServer) error {
	ctx := stream.Context()
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	wctx, cancel := context.WithTimeout(ctx, shellWait)
	sess := b.s.shells.wait(wctx, first.GetJobId())
	cancel()
	if sess == nil || sess.tenant != first.GetTenantId() {
		return status.Error(codes.NotFound, "the agent has not opened the session")
	}
	sess.mu.Lock()
	if sess.attached {
		sess.mu.Unlock()
		return status.Error(codes.AlreadyExists, "the session is already attached")
	}
	sess.attached = true
	sess.mu.Unlock()
	defer func() {
		sess.mu.Lock()
		sess.attached = false
		sess.mu.Unlock()
	}()
	go func() {
		for {
			f, err := stream.Recv()
			if err != nil {
				return
			}
			select {
			case sess.toAgent <- &openrmmv1.ShellFrame{Data: f.GetData(), Cols: f.GetCols(), Rows: f.GetRows(), Close: f.GetClose()}:
			case <-sess.done:
				return
			}
		}
	}()
	for {
		select {
		case f := <-sess.fromAgent:
			if err := stream.Send(f); err != nil {
				return err
			}
			if f.GetClose() {
				return nil
			}
		case <-sess.done:
			// Drain what the agent sent last.
			for {
				select {
				case f := <-sess.fromAgent:
					_ = stream.Send(f)
				default:
					return stream.Send(&openrmmv1.ShellFrame{Close: true})
				}
			}
		case <-ctx.Done():
			return nil
		}
	}
}
