package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/ids"
)

const moduleChunkSize = 512 << 10

// Run listens for job notifications and wakes the sessions concerned. It
// blocks until ctx ends, reconnecting the listener after errors.
func (s *Server) Run(ctx context.Context) {
	for ctx.Err() == nil {
		err := s.store.ListenJobs(ctx, s.wake)
		if ctx.Err() != nil {
			return
		}
		s.log.Error("job listener stopped, restarting", "err", err)
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Second):
		}
	}
}

func (s *Server) wake(key string) {
	s.mu.Lock()
	var targets []*session
	if tenant, ok := strings.CutSuffix(key, "/*"); ok {
		for k, sess := range s.sessions {
			if strings.HasPrefix(k, tenant+"/") {
				targets = append(targets, sess)
			}
		}
	} else if sess := s.sessions[key]; sess != nil {
		targets = append(targets, sess)
	}
	s.mu.Unlock()
	for _, sess := range targets {
		select {
		case sess.wake <- struct{}{}:
		default: // a wake-up is already pending
		}
	}
}

// dispatch sends the agent's pending jobs it has not received in this session.
func (s *Server) dispatch(ctx context.Context, stream openrmmv1.AgentService_ConnectServer, a store.Agent, sent map[string]bool) error {
	jobs, err := s.store.DispatchableJobs(ctx, a.TenantID, a.ID, s.now())
	if err != nil {
		s.log.Error("load jobs", "agent", a.ID, "err", err)
		return nil
	}
	for _, j := range jobs {
		if sent[j.ID] {
			continue
		}
		env := &openrmmv1.SignedEnvelope{}
		if err := proto.Unmarshal(j.Envelope, env); err != nil {
			s.log.Error("stored job envelope corrupt", "job", j.ID, "err", err)
			continue
		}
		if err := stream.Send(&openrmmv1.ConsoleMessage{Msg: &openrmmv1.ConsoleMessage_Job{Job: env}}); err != nil {
			return err
		}
		sent[j.ID] = true
		if err := s.store.MarkJobSent(ctx, a.TenantID, j.ID, s.now()); err != nil {
			s.log.Error("mark job sent", "job", j.ID, "err", err)
		}
		s.log.Info("job sent", "agent", a.ID, "job", j.ID, "module", j.Module, "action", j.Action)
	}
	return nil
}

var protoStates = map[openrmmv1.JobUpdate_State]store.JobState{
	openrmmv1.JobUpdate_STATE_ACCEPTED:  store.JobAccepted,
	openrmmv1.JobUpdate_STATE_REJECTED:  store.JobRejected,
	openrmmv1.JobUpdate_STATE_RUNNING:   store.JobRunning,
	openrmmv1.JobUpdate_STATE_SUCCEEDED: store.JobSucceeded,
	openrmmv1.JobUpdate_STATE_FAILED:    store.JobFailed,
}

func clip(s string, n int) string {
	if !utf8.ValidString(s) {
		s = "(invalid UTF-8)"
	}
	if len(s) > n {
		return s[:n]
	}
	return s
}

// recordJobUpdate stores an update and reports whether to acknowledge it.
// Final updates are acknowledged once stored, or when they can never be
// stored (unknown job), so that the agent stops resending them.
func (s *Server) recordJobUpdate(ctx context.Context, a store.Agent, u *openrmmv1.JobUpdate) bool {
	state, ok := protoStates[u.GetState()]
	if !ok || !ids.IsUUID(u.GetJobId()) {
		s.log.Warn("invalid job update", "agent", a.ID)
		return false
	}
	upd := store.JobUpdate{
		State:    state,
		Progress: max(0, min(100, int(u.GetProgressPercent()))),
		Message:  clip(u.GetMessage(), 500),
		Error:    clip(u.GetError(), 8000),
	}
	if state == store.JobSucceeded {
		if !json.Valid(u.GetResultJson()) {
			upd.State, upd.Error = store.JobFailed, "agent returned an invalid JSON result"
		} else {
			upd.Result = u.GetResultJson()
		}
	}
	err := s.store.UpdateJob(ctx, a.TenantID, a.ID, u.GetJobId(), upd, s.now())
	final := upd.State.Final()
	switch {
	case err == nil:
		if final {
			s.log.Info("job finished", "agent", a.ID, "job", u.GetJobId(), "state", upd.State)
			s.audit(ctx, a.TenantID, "agent:"+a.ID, "job.finished", u.GetJobId(), map[string]any{
				"state": string(upd.State), "error": clip(upd.Error, 500),
			})
		}
		return final
	case errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrJobFinal):
		s.log.Warn("job update ignored", "agent", a.ID, "job", u.GetJobId(), "reason", err)
		return final
	default:
		s.log.Error("store job update", "job", u.GetJobId(), "err", err)
		return false
	}
}

// GetModule streams a module to an approved agent.
func (s *Server) GetModule(req *openrmmv1.GetModuleRequest, stream openrmmv1.AgentService_GetModuleServer) error {
	c, ok := callerFromContext(stream.Context())
	if !ok {
		return status.Error(codes.Unauthenticated, "unauthenticated")
	}
	if c.agent.Status != store.AgentActive {
		return status.Error(codes.PermissionDenied, "agent not approved")
	}
	m, err := s.store.GetModule(stream.Context(), req.GetModule(), req.GetVersion())
	if errors.Is(err, store.ErrNotFound) {
		return status.Error(codes.NotFound, "module not found")
	}
	if err != nil {
		s.log.Error("load module", "err", err)
		return status.Error(codes.Unavailable, "temporarily unavailable")
	}
	first := &openrmmv1.ModuleChunk{Manifest: &openrmmv1.SignedEnvelope{KeyId: m.KeyID, Payload: m.Manifest, Signature: m.Signature}}
	data := m.Archive
	for {
		n := min(len(data), moduleChunkSize)
		chunk := &openrmmv1.ModuleChunk{Data: data[:n]}
		if first != nil {
			chunk.Manifest, first = first.Manifest, nil
		}
		if err := stream.Send(chunk); err != nil {
			return err
		}
		data = data[n:]
		if len(data) == 0 {
			return nil
		}
	}
}
