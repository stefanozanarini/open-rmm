// Package signer implements openrmm-signer: the only holder of the job
// signing key. It signs a job only if the request carries an id_token that
//
//   - is valid (signature, issuer, audience, expiry) for the console app,
//   - was issued with multi-factor authentication, recently,
//   - has a nonce equal to the canonical hash of this exact request,
//   - has never been used before,
//   - belongs to an operator with the Operator or Admin role, allowed on
//     the request's tenant.
//
// None of this depends on the console being honest.
package signer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/open-rmm/internal/console/authn"
	"github.com/stefanozanarini/open-rmm/internal/console/jobreq"
	"github.com/stefanozanarini/open-rmm/internal/ids"
	"github.com/stefanozanarini/open-rmm/internal/policy"
	"github.com/stefanozanarini/open-rmm/internal/signing"
)

// Server implements openrmmv1.SignerServiceServer.
type Server struct {
	openrmmv1.UnimplementedSignerServiceServer

	signer   *signing.Signer
	verifier *authn.Verifier
	log      *slog.Logger
	now      func() time.Time
	used     *usedTokens
}

// New returns a signer. stateFile persists the used-token register.
func New(signer *signing.Signer, verifier *authn.Verifier, stateFile string, log *slog.Logger) (*Server, error) {
	used, err := loadUsed(stateFile)
	if err != nil {
		return nil, err
	}
	return &Server{signer: signer, verifier: verifier, log: log, now: time.Now, used: used}, nil
}

// SignJob verifies the operator's approval and signs the job.
func (s *Server) SignJob(ctx context.Context, req *openrmmv1.SignJobRequest) (*openrmmv1.SignJobResponse, error) {
	r := req.GetRequest()
	deny := func(reason string, err error) (*openrmmv1.SignJobResponse, error) {
		s.log.Warn("signature refused", "reason", reason, "err", err, "tenant", r.GetTenantId(),
			"agent", r.GetAgentId(), "module", r.GetModule(), "action", r.GetAction())
		return nil, status.Error(codes.PermissionDenied, reason)
	}
	if err := jobreq.Validate(r); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	claims, err := s.verifier.Verify(ctx, req.GetIdToken())
	if err != nil {
		return deny("operator authentication rejected", err)
	}
	now := s.now()
	if err := s.verifier.CheckFresh(claims, now); err != nil {
		return deny("authentication too old", err)
	}
	if !jobreq.CheckAuthNonce(claims.Nonce, r) {
		return deny("authentication was not issued for this request", authn.ErrNonce)
	}
	if !claims.HasRole(authn.RoleOperator, authn.RoleAdmin) {
		return deny("operator may not run jobs", authn.ErrNoRole)
	}
	if !s.verifier.MayManage(claims, r.GetTenantId()) {
		return deny("operator may not manage this tenant", authn.ErrNoTenant)
	}
	// One authentication approves one job.
	if err := s.used.add(claims.Nonce, now.Add(2*time.Hour), now); err != nil {
		return deny("authentication already used", err)
	}

	ttl := time.Duration(r.GetTtlSeconds()) * time.Second
	op := claims.Operator()
	resp := &openrmmv1.SignJobResponse{Operator: op}
	for _, agent := range jobreq.Targets(r) {
		job := &openrmmv1.Job{
			JobId: ids.NewUUID(), TenantId: r.GetTenantId(), AgentId: agent,
			Module: r.GetModule(), ModuleVersion: r.GetModuleVersion(), ModuleSha256: r.GetModuleSha256(),
			Action: r.GetAction(), ParamsJson: r.GetParamsJson(), Packages: r.GetPackages(),
			NotBeforeUnix: now.Add(-time.Minute).Unix(), ExpiresUnix: now.Add(ttl).Unix(),
			Nonce: ids.Random(16),
		}
		payload, err := proto.Marshal(job)
		if err != nil {
			return nil, status.Error(codes.Internal, "encode job")
		}
		env, err := proto.Marshal(&openrmmv1.SignedEnvelope{KeyId: s.signer.KeyID(), Payload: payload,
			Signature: s.signer.Sign(signing.DomainJob, payload)})
		if err != nil {
			return nil, status.Error(codes.Internal, "encode envelope")
		}
		resp.Jobs = append(resp.Jobs, &openrmmv1.SignedJob{JobId: job.GetJobId(), AgentId: agent, Envelope: env})
		resp.ExpiresUnix = job.GetExpiresUnix()
		// The signer's own log is an audit trail independent of the console.
		s.log.Info("job signed", "job", job.GetJobId(), "operator", op, "tenant", r.GetTenantId(), "agent", agent,
			"module", r.GetModule(), "version", r.GetModuleVersion(), "action", r.GetAction(),
			"params_sha256", fmt.Sprintf("%x", sha256.Sum256(r.GetParamsJson())), "packages", len(r.GetPackages()))
	}
	if len(resp.Jobs) == 1 {
		resp.JobId, resp.Envelope = resp.Jobs[0].GetJobId(), resp.Jobs[0].GetEnvelope()
	}
	return resp, nil
}

// usedTokens remembers consumed step-up nonces until their tokens expire.
type usedTokens struct {
	mu   sync.Mutex
	path string
	seen map[string]int64
}

var errUsed = errors.New("token already used")

func loadUsed(path string) (*usedTokens, error) {
	u := &usedTokens{path: path, seen: map[string]int64{}}
	raw, err := os.ReadFile(path) // #nosec G304 -- configured state file
	switch {
	case err == nil:
		if err := json.Unmarshal(raw, &u.seen); err != nil {
			return nil, fmt.Errorf("used-token register corrupt: %w", err)
		}
	case !errors.Is(err, os.ErrNotExist):
		return nil, err
	}
	return u, nil
}

func (u *usedTokens) add(nonce string, until, now time.Time) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if _, ok := u.seen[nonce]; ok {
		return errUsed
	}
	for k, exp := range u.seen {
		if exp < now.Unix() {
			delete(u.seen, k)
		}
	}
	u.seen[nonce] = until.Unix()
	raw, err := json.Marshal(u.seen)
	if err != nil {
		return err
	}
	tmp := u.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		delete(u.seen, nonce)
		return err
	}
	if err := os.Rename(tmp, u.path); err != nil {
		delete(u.seen, nonce)
		return err
	}
	return nil
}

// SignPolicy verifies the operator's approval of a policy document and signs
// it. Policies act on many endpoints for a long time, so they need the Admin
// role; the approval is bound to the exact document bytes.
func (s *Server) SignPolicy(ctx context.Context, req *openrmmv1.SignPolicyRequest) (*openrmmv1.SignPolicyResponse, error) {
	deny := func(reason string, err error) (*openrmmv1.SignPolicyResponse, error) {
		s.log.Warn("policy signature refused", "reason", reason, "err", err, "tenant", req.GetTenantId())
		return nil, status.Error(codes.PermissionDenied, reason)
	}
	raw := req.GetPolicyJson()
	if len(raw) > 1<<20 {
		return nil, status.Error(codes.InvalidArgument, "policy too large")
	}
	p, err := policy.Parse(raw)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	canon, err := p.Canonical()
	if err != nil || !bytes.Equal(canon, raw) {
		return nil, status.Error(codes.InvalidArgument, "policy document is not canonical")
	}
	if p.TenantID != req.GetTenantId() {
		return nil, status.Error(codes.InvalidArgument, "tenant mismatch")
	}
	claims, err := s.verifier.Verify(ctx, req.GetIdToken())
	if err != nil {
		return deny("operator authentication rejected", err)
	}
	now := s.now()
	if err := s.verifier.CheckFresh(claims, now); err != nil {
		return deny("authentication too old", err)
	}
	if subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(policy.AuthNonce(raw))) != 1 {
		return deny("authentication was not issued for this policy", authn.ErrNonce)
	}
	if !claims.HasRole(authn.RoleAdmin) {
		return deny("only administrators may approve policies", authn.ErrNoRole)
	}
	if !s.verifier.MayManage(claims, p.TenantID) {
		return deny("operator may not manage this tenant", authn.ErrNoTenant)
	}
	if err := s.used.add(claims.Nonce, now.Add(2*time.Hour), now); err != nil {
		return deny("authentication already used", err)
	}
	env, err := proto.Marshal(&openrmmv1.SignedEnvelope{KeyId: s.signer.KeyID(), Payload: raw,
		Signature: s.signer.Sign(signing.DomainPolicy, raw)})
	if err != nil {
		return nil, status.Error(codes.Internal, "encode envelope")
	}
	op := claims.Operator()
	s.log.Info("policy signed", "policy", p.ID, "version", p.Version, "name", p.Name, "tenant", p.TenantID,
		"rules", len(p.Rules), "operator", op, "sha256", fmt.Sprintf("%x", sha256.Sum256(raw)))
	return &openrmmv1.SignPolicyResponse{Envelope: env, Operator: op}, nil
}
