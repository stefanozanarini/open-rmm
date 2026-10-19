package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"google.golang.org/protobuf/proto"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/ids"
)

// sendPolicies sends the tenant's current policy set when it differs from
// the last one sent in this session. The agent filters by OS family itself.
func (s *Server) sendPolicies(ctx context.Context, stream openrmmv1.AgentService_ConnectServer, a store.Agent, last *[]byte) error {
	cur, err := s.store.CurrentPolicies(ctx, a.TenantID)
	if err != nil {
		s.log.Error("load policies", "err", err)
		return nil
	}
	set := &openrmmv1.PolicySet{}
	h := sha256.New()
	for _, p := range cur {
		env := &openrmmv1.SignedEnvelope{}
		if err := proto.Unmarshal(p.Envelope, env); err != nil {
			s.log.Error("stored policy envelope corrupt", "policy", p.ID, "err", err)
			continue
		}
		set.Policies = append(set.Policies, env)
		h.Write(p.Envelope)
	}
	sum := h.Sum(nil)
	if *last != nil && bytes.Equal(*last, sum) {
		return nil
	}
	if err := stream.Send(&openrmmv1.ConsoleMessage{Msg: &openrmmv1.ConsoleMessage_PolicySet{PolicySet: set}}); err != nil {
		return err
	}
	*last = sum
	return nil
}

var policyStates = map[openrmmv1.JobUpdate_State]store.JobState{
	openrmmv1.JobUpdate_STATE_SUCCEEDED: store.JobSucceeded,
	openrmmv1.JobUpdate_STATE_FAILED:    store.JobFailed,
	openrmmv1.JobUpdate_STATE_REJECTED:  store.JobRejected,
}

// recordPolicyResult stores a rule result and reports whether to ack it.
func (s *Server) recordPolicyResult(ctx context.Context, a store.Agent, r *openrmmv1.PolicyResult) bool {
	state, ok := policyStates[r.GetState()]
	if !ok || !ids.IsUUID(r.GetRunId()) || !ids.IsUUID(r.GetPolicyId()) || len(r.GetRuleId()) > 41 {
		s.log.Warn("invalid policy result", "agent", a.ID)
		return ids.IsUUID(r.GetRunId()) // drop it from the agent's outbox anyway
	}
	res := store.PolicyResult{TenantID: a.TenantID, AgentID: a.ID, PolicyID: r.GetPolicyId(), RuleID: r.GetRuleId(),
		PolicyVersion: r.GetPolicyVersion(), RunID: r.GetRunId(), State: state, Error: clip(r.GetError(), 8000),
		StartedAt: time.UnixMilli(r.GetStartedUnixMs()), FinishedAt: time.UnixMilli(r.GetFinishedUnixMs())}
	if state == store.JobSucceeded {
		if json.Valid(r.GetResultJson()) {
			res.Result = r.GetResultJson()
		} else {
			res.State, res.Error = store.JobFailed, "agent returned an invalid JSON result"
		}
	}
	err := s.store.PutPolicyResult(ctx, res)
	switch {
	case err == nil:
		if res.State == store.JobSucceeded && s.isInventoryRule(ctx, a.TenantID, res.PolicyID, res.RuleID) {
			s.ingestInventory(ctx, a, res.Result)
		}
		return true
	case errors.Is(err, store.ErrNotFound):
		return true
	default:
		s.log.Error("store policy result", "err", err)
		return false
	}
}
