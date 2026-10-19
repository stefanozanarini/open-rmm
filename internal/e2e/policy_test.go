package e2e

import (
	"context"
	"encoding/hex"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/open-rmm/internal/agent/policies"
	"github.com/stefanozanarini/open-rmm/internal/console/authn"
	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/ids"
	"github.com/stefanozanarini/open-rmm/internal/modules"
	"github.com/stefanozanarini/open-rmm/internal/policy"
	"github.com/stefanozanarini/open-rmm/internal/signing"
)

func fastPolicies(t *testing.T) {
	oldTick, oldSpread := policies.Tick, policies.FirstRunSpread
	policies.Tick, policies.FirstRunSpread = 50*time.Millisecond, 10*time.Millisecond
	t.Cleanup(func() { policies.Tick, policies.FirstRunSpread = oldTick, oldSpread })
}

func ruleFor(v *modules.Verified, id, action string, when *policy.Condition) policy.Rule {
	return policy.Rule{ID: id, Module: v.Manifest.ID, ModuleVersion: v.Manifest.Version,
		ModuleSHA256: hex.EncodeToString(v.ManifestHash), Action: action, EverySeconds: 60, When: when}
}

// publishPolicy signs a policy with the job/policy key (as the signer
// would after MFA approval) and stores it.
func (e *env) publishPolicy(t *testing.T, p *policy.Policy) {
	t.Helper()
	raw, err := p.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	env, _ := proto.Marshal(&openrmmv1.SignedEnvelope{KeyId: e.jobSigner.KeyID(), Payload: raw,
		Signature: e.jobSigner.Sign(signing.DomainPolicy, raw)})
	if err := e.store.AddPolicyVersion(context.Background(), store.PolicyVersion{TenantID: p.TenantID, ID: p.ID,
		Version: p.Version, Name: p.Name, AppliesTo: p.AppliesTo, Document: raw, Envelope: env, CreatedBy: "test"}); err != nil {
		t.Fatal(err)
	}
}

func (e *env) results(t *testing.T, agentID string) map[string]store.PolicyResult {
	rs, _ := e.store.ListPolicyResults(context.Background(), e.tenant, agentID)
	out := map[string]store.PolicyResult{}
	for _, r := range rs {
		out[r.RuleID] = r
	}
	return out
}

func TestPolicyRunsWhereConditionsHold(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("uses the sh entrypoint")
	}
	fastPolicies(t)
	e := start(t)
	v := e.publish(t, filepath.Join(repoRoot(t), "modules", "sysinfo"))
	_, agentID := startAgent(t, e, true)
	pid := ids.NewUUID()
	e.publishPolicy(t, &policy.Policy{ID: pid, TenantID: e.tenant, Name: "Baseline", Version: 1, AppliesTo: policy.AppliesAll,
		Rules: []policy.Rule{
			ruleFor(v, "present", "info", &policy.Condition{FileExists: "/"}),
			ruleFor(v, "absent", "info", &policy.Condition{FileExists: "/nonexistent/open-rmm"}),
		}})
	waitForWithin(t, func() bool { return e.results(t, agentID)["present"].State == store.JobSucceeded }, 10*time.Second)
	r := e.results(t, agentID)["present"]
	if !strings.Contains(string(r.Result), "hostname") || r.PolicyVersion != 1 {
		t.Fatalf("result = %+v", r)
	}
	time.Sleep(300 * time.Millisecond)
	if _, ran := e.results(t, agentID)["absent"]; ran {
		t.Fatal("rule ran although its condition is false")
	}

	// A new version is delivered to the connected agent and replaces the old.
	e.publishPolicy(t, &policy.Policy{ID: pid, TenantID: e.tenant, Name: "Baseline", Version: 2, AppliesTo: policy.AppliesAll,
		Rules: []policy.Rule{ruleFor(v, "v2", "info", nil)}})
	waitForWithin(t, func() bool { return e.results(t, agentID)["v2"].PolicyVersion == 2 }, 10*time.Second)
}

func TestPoliciesCannotScheduleAdHocScripts(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("uses the sh entrypoint")
	}
	fastPolicies(t)
	e := start(t)
	v := e.publish(t, shModule(t, strings.ReplaceAll(adhocManifest, "PLATFORM", platform()),
		`. "$OPENRMM_MODULE_DIR/_sdk/openrmm.sh"; rmm_read_request; rmm_result '{"ran":true}'`))
	_, agentID := startAgent(t, e, true)
	e.publishPolicy(t, &policy.Policy{ID: ids.NewUUID(), TenantID: e.tenant, Name: "Bad", Version: 1, AppliesTo: policy.AppliesAll,
		Rules: []policy.Rule{ruleFor(v, "script", "run", nil)}})
	waitForWithin(t, func() bool { return e.results(t, agentID)["script"].State != "" }, 10*time.Second)
	if r := e.results(t, agentID)["script"]; r.State != store.JobRejected || !strings.Contains(r.Error, "ad-hoc") {
		t.Fatalf("ad-hoc module in a policy: %s %q", r.State, r.Error)
	}
}

func TestSignerPolicyApproval(t *testing.T) {
	e := startConsole(t)
	ctx := context.Background()
	p := &policy.Policy{ID: ids.NewUUID(), TenantID: e.tenant, Name: "Baseline", Version: 1, AppliesTo: policy.AppliesServers,
		Rules: []policy.Rule{ruleFor(e.module, "info", "info", nil)}}
	raw, _ := p.Canonical()

	// An operator (not admin) cannot approve policies.
	op := admin
	op.Roles = []string{authn.RoleOperator}
	if _, err := e.signer.SignPolicy(ctx, &openrmmv1.SignPolicyRequest{TenantId: e.tenant, PolicyJson: raw,
		IdToken: e.tokenFor(t, op, policy.AuthNonce(raw))}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("operator approval: %v", err)
	}
	// The approval covers exactly the approved document.
	tok := e.tokenFor(t, admin, policy.AuthNonce(raw))
	p2 := *p
	p2.AppliesTo = policy.AppliesAll
	raw2, _ := p2.Canonical()
	if _, err := e.signer.SignPolicy(ctx, &openrmmv1.SignPolicyRequest{TenantId: e.tenant, PolicyJson: raw2, IdToken: tok}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("approval reused for another document: %v", err)
	}
	// Non-canonical bytes are refused (what is signed must be what was hashed).
	if _, err := e.signer.SignPolicy(ctx, &openrmmv1.SignPolicyRequest{TenantId: e.tenant, PolicyJson: append([]byte(" "), raw...),
		IdToken: tok}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("non-canonical document: %v", err)
	}
	resp, err := e.signer.SignPolicy(ctx, &openrmmv1.SignPolicyRequest{TenantId: e.tenant, PolicyJson: raw, IdToken: tok})
	if err != nil {
		t.Fatal(err)
	}
	env := &openrmmv1.SignedEnvelope{}
	proto.Unmarshal(resp.GetEnvelope(), env)
	pk := signing.NewKeyring()
	pub, _ := signing.ParsePublicKey(pubKey(e.jobSignerOf(t)))
	pk.Add(pub, signing.DomainPolicy)
	if err := pk.Verify(signing.DomainPolicy, env.GetKeyId(), env.GetPayload(), env.GetSignature()); err != nil {
		t.Fatalf("policy signature: %v", err)
	}
	if _, err := e.signer.SignPolicy(ctx, &openrmmv1.SignPolicyRequest{TenantId: e.tenant, PolicyJson: raw, IdToken: tok}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("approval replayed: %v", err)
	}
}
