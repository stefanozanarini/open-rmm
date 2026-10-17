package gateway

import (
	"context"
	"errors"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/release"
)

const releaseChunkSize = 512 << 10

func platformOf(a store.Agent) string { return a.Host.OS + "/" + a.Host.Arch }

// targetFor returns the release the agent should run, if it is not running it.
func (s *Server) targetFor(ctx context.Context, a store.Agent) (store.Release, bool) {
	if a.Status != store.AgentActive {
		return store.Release{}, false
	}
	ring := a.UpdateRing
	if ring == "" {
		ring = store.RingBroad
	}
	t, err := s.store.GetReleaseTarget(ctx, a.TenantID, ring, platformOf(a))
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			s.log.Error("release target", "err", err)
		}
		return store.Release{}, false
	}
	want, err := release.ParseVersion(t.Version)
	if err != nil || !release.ParseRunning(a.Host.AgentVersion).Less(want) {
		return store.Release{}, false
	}
	r, err := s.store.GetRelease(ctx, t.Version, t.Platform)
	if err != nil {
		s.log.Error("release", "err", err)
		return store.Release{}, false
	}
	return r, true
}

// offerUpdate proposes the target release once per session.
func (s *Server) offerUpdate(ctx context.Context, stream openrmmv1.AgentService_ConnectServer, a store.Agent, offered map[string]bool) error {
	r, ok := s.targetFor(ctx, a)
	if !ok || offered[r.Version] {
		return nil
	}
	offered[r.Version] = true
	s.log.Info("offering agent update", "agent", a.ID, "from", a.Host.AgentVersion, "to", r.Version)
	return stream.Send(&openrmmv1.ConsoleMessage{Msg: &openrmmv1.ConsoleMessage_AgentUpdate{AgentUpdate: &openrmmv1.AgentUpdateOffer{
		Manifest: &openrmmv1.SignedEnvelope{KeyId: r.KeyID, Payload: r.Manifest, Signature: r.Signature},
	}}})
}

var updateStates = map[openrmmv1.UpdateStatus_State]string{
	openrmmv1.UpdateStatus_STATE_DOWNLOADING: "downloading",
	openrmmv1.UpdateStatus_STATE_STAGED:      "staged",
	openrmmv1.UpdateStatus_STATE_APPLIED:     "applied",
	openrmmv1.UpdateStatus_STATE_REJECTED:    "rejected",
	openrmmv1.UpdateStatus_STATE_ROLLED_BACK: "rolled_back",
}

func (s *Server) recordUpdateStatus(ctx context.Context, a store.Agent, u *openrmmv1.UpdateStatus) {
	state, ok := updateStates[u.GetState()]
	if !ok {
		return
	}
	upd := store.AgentUpdate{State: state, Version: clip(u.GetVersion(), 20), Error: clip(u.GetError(), 2000), At: s.now()}
	if err := s.store.SetAgentUpdate(ctx, a.TenantID, a.ID, upd); err != nil {
		s.log.Error("store update status", "err", err)
	}
	s.log.Info("agent update status", "agent", a.ID, "state", state, "version", upd.Version, "error", upd.Error)
	switch state {
	case "applied", "rolled_back", "rejected":
		s.audit(ctx, a.TenantID, "agent:"+a.ID, "agent.update_"+state, a.ID, map[string]any{
			"version": upd.Version, "error": upd.Error})
	}
}

// GetAgentRelease streams the release currently targeted for the calling
// agent; other versions are refused.
func (s *Server) GetAgentRelease(req *openrmmv1.GetAgentReleaseRequest, stream openrmmv1.AgentService_GetAgentReleaseServer) error {
	c, ok := callerFromContext(stream.Context())
	if !ok {
		return status.Error(codes.Unauthenticated, "unauthenticated")
	}
	ctx := stream.Context()
	cur, err := s.store.GetAgent(ctx, c.agent.TenantID, c.agent.ID)
	if err != nil {
		return status.Error(codes.Unavailable, "temporarily unavailable")
	}
	r, ok := s.targetFor(ctx, cur)
	if !ok || r.Version != req.GetVersion() || r.Platform != req.GetPlatform() {
		return status.Error(codes.PermissionDenied, "release not targeted for this agent")
	}
	goos, _, _ := strings.Cut(r.Platform, "/")
	for _, name := range []string{release.AgentFile(goos), release.WatchdogFile(goos)} {
		data, err := s.store.GetReleaseFile(ctx, r.Version, r.Platform, name)
		if err != nil {
			s.log.Error("release file", "file", name, "err", err)
			return status.Error(codes.Unavailable, "temporarily unavailable")
		}
		for len(data) > 0 {
			n := min(len(data), releaseChunkSize)
			if err := stream.Send(&openrmmv1.ReleaseChunk{File: name, Data: data[:n]}); err != nil {
				return err
			}
			data = data[n:]
		}
	}
	return nil
}
