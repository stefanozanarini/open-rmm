package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/open-rmm/internal/agent/config"
	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/ids"
	"github.com/stefanozanarini/open-rmm/internal/modules"
	"github.com/stefanozanarini/open-rmm/internal/signing"
)

func newSigner(t *testing.T) *signing.Signer {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, err := signing.NewSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	signerMu.Lock()
	signerPublic[s] = pub
	signerMu.Unlock()
	return s
}

func pubKey(s *signing.Signer) string {
	signerMu.Lock()
	defer signerMu.Unlock()
	return signing.EncodePublicKey(signerPublic[s])
}

// signerPublic remembers the public half of the test signers.
var (
	signerMu     sync.Mutex
	signerPublic = map[*signing.Signer]ed25519.PublicKey{}
)

func (e *env) keysJSON() string {
	return `"job_signing_keys":["` + pubKey(e.jobSigner) + `"],"module_signing_keys":["` + pubKey(e.moduleSigner) +
		`"],"release_signing_keys":["` + pubKey(e.releaseSigner) + `"]`
}

// publish packs dir (with the repository SDK), signs it and publishes it.
func (e *env) publish(t *testing.T, dir string) *modules.Verified {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m modules.Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	sdk, _ := os.ReadFile(filepath.Join(repoRoot(t), "modules", "sdk", "sh", "openrmm.sh"))
	archive, err := modules.Pack(&m, dir, map[string][]byte{"_sdk/openrmm.sh": sdk})
	if err != nil {
		t.Fatal(err)
	}
	b, err := modules.SignBundle(e.moduleSigner, &m, archive)
	if err != nil {
		t.Fatal(err)
	}
	keys := signing.NewKeyring()
	pub, _ := signing.ParsePublicKey(pubKey(e.moduleSigner))
	keys.Add(pub, signing.DomainModuleManifest)
	v, err := b.Verify(keys)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.store.PutModule(context.Background(), store.Module{ID: m.ID, Version: m.Version, KeyID: b.KeyID,
		Manifest: b.Manifest, Signature: b.Signature, ManifestSHA256: v.ManifestHash, Archive: b.Archive}); err != nil {
		t.Fatal(err)
	}
	return v
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, _ := os.Getwd()
	return filepath.Join(wd, "..", "..")
}

// queue signs and queues a job, like openrmm-admin job run.
func (e *env) queue(t *testing.T, agentID string, v *modules.Verified, action, params string) string {
	t.Helper()
	now := time.Now()
	job := &openrmmv1.Job{JobId: ids.NewUUID(), TenantId: e.tenant, AgentId: agentID,
		Module: v.Manifest.ID, ModuleVersion: v.Manifest.Version, ModuleSha256: v.ManifestHash,
		Action: action, ParamsJson: []byte(params),
		NotBeforeUnix: now.Add(-time.Minute).Unix(), ExpiresUnix: now.Add(time.Hour).Unix(), Nonce: ids.Random(16)}
	payload, _ := proto.Marshal(job)
	env, _ := proto.Marshal(&openrmmv1.SignedEnvelope{KeyId: e.jobSigner.KeyID(), Payload: payload,
		Signature: e.jobSigner.Sign(signing.DomainJob, payload)})
	if err := e.store.CreateJob(context.Background(), store.Job{TenantID: e.tenant, ID: job.GetJobId(), AgentID: agentID,
		Module: job.GetModule(), ModuleVersion: job.GetModuleVersion(), Action: action, Params: []byte(params),
		Envelope: env, CreatedBy: "test", ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	return job.GetJobId()
}

func (e *env) waitFinal(t *testing.T, jobID string) store.Job {
	t.Helper()
	var j store.Job
	waitFor(t, func() bool {
		j, _ = e.store.GetJob(context.Background(), e.tenant, jobID)
		return j.State.Final()
	})
	return j
}

func shModule(t *testing.T, manifest, script string) string {
	t.Helper()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(manifest), 0o600)
	os.WriteFile(filepath.Join(dir, "main.sh"), []byte(script), 0o600)
	return dir
}

func platform() string { return runtime.GOOS + "/" + runtime.GOARCH }

func startAgent(t *testing.T, e *env, autoApprove bool) (*config.Config, string) {
	t.Helper()
	cfg := e.agentConfig(t, e.tokenWith(t, 1, autoApprove))
	runAgent(t, cfg)
	return cfg, e.onlyAgent(t).ID
}

func TestSysinfoModuleEndToEnd(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("uses the sh entrypoint")
	}
	e := start(t)
	v := e.publish(t, filepath.Join(repoRoot(t), "modules", "sysinfo"))
	cfg, agentID := startAgent(t, e, true)
	j := e.waitFinal(t, e.queue(t, agentID, v, "info", "{}"))
	if j.State != store.JobSucceeded {
		t.Fatalf("job %s: %s", j.State, j.Error)
	}
	var res struct {
		Hostname      string `json:"hostname"`
		Kernel        string `json:"kernel"`
		UptimeSeconds int64  `json:"uptime_seconds"`
	}
	if err := json.Unmarshal(j.Result, &res); err != nil || res.Hostname == "" || res.Kernel == "" {
		t.Fatalf("result %s: %v", j.Result, err)
	}
	// The final update was acknowledged, so the outbox is empty again.
	waitFor(t, func() bool {
		entries, _ := os.ReadDir(filepath.Join(cfg.DataDir, "outbox"))
		return len(entries) == 0
	})
	// A second job reuses the cached module.
	if j := e.waitFinal(t, e.queue(t, agentID, v, "info", "{}")); j.State != store.JobSucceeded {
		t.Fatalf("second job %s: %s", j.State, j.Error)
	}
}

const failingManifest = `{"id":"fails","version":"1.0.0","protocol_version":1,
 "entrypoints":{"PLATFORM":{"type":"sh","path":"main.sh"}},"actions":{"run":{"timeout_seconds":30}}}`

func TestFailingModuleReportsError(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("uses the sh entrypoint")
	}
	e := start(t)
	v := e.publish(t, shModule(t, strings.ReplaceAll(failingManifest, "PLATFORM", platform()),
		`. "$OPENRMM_MODULE_DIR/_sdk/openrmm.sh"; rmm_read_request; echo oops >&2; rmm_error "disk \"C:\" not found"; exit 2`))
	_, agentID := startAgent(t, e, true)
	j := e.waitFinal(t, e.queue(t, agentID, v, "run", "{}"))
	if j.State != store.JobFailed || !strings.Contains(j.Error, `disk "C:" not found`) || !strings.Contains(j.Error, "oops") {
		t.Fatalf("job %s: %q", j.State, j.Error)
	}
}

const adhocManifest = `{"id":"shell","version":"1.0.0","protocol_version":1,"capabilities":["adhoc_script"],
 "entrypoints":{"PLATFORM":{"type":"sh","path":"main.sh"}},"actions":{"run":{}}}`

func TestLocalPolicyBlocksAdHocScripts(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("uses the sh entrypoint")
	}
	e := start(t)
	v := e.publish(t, shModule(t, strings.ReplaceAll(adhocManifest, "PLATFORM", platform()),
		`. "$OPENRMM_MODULE_DIR/_sdk/openrmm.sh"; rmm_read_request; rmm_result '{"ran":true}'`))
	cfg := e.agentConfig(t, e.tokenWith(t, 1, true))
	off := false
	cfg.AllowAdHocScripts = &off
	runAgent(t, cfg)
	j := e.waitFinal(t, e.queue(t, e.onlyAgent(t).ID, v, "run", "{}"))
	if j.State != store.JobRejected || !strings.Contains(j.Error, "local policy") {
		t.Fatalf("job %s: %q", j.State, j.Error)
	}
}

func TestPendingAgentGetsJobsOnlyAfterApproval(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("uses the sh entrypoint")
	}
	e := start(t)
	v := e.publish(t, filepath.Join(repoRoot(t), "modules", "sysinfo"))
	_, agentID := startAgent(t, e, false)
	jobID := e.queue(t, agentID, v, "info", "{}")
	time.Sleep(500 * time.Millisecond)
	if j, _ := e.store.GetJob(context.Background(), e.tenant, jobID); j.State != store.JobQueued {
		t.Fatalf("job delivered to a pending agent: %s", j.State)
	}
	// Approval wakes the session: the job runs without waiting for a heartbeat.
	if err := e.store.ApproveAgent(context.Background(), e.tenant, agentID, "test", time.Now()); err != nil {
		t.Fatal(err)
	}
	if j := e.waitFinal(t, jobID); j.State != store.JobSucceeded {
		t.Fatalf("job %s: %s", j.State, j.Error)
	}
}

func TestTamperedModuleCacheIsReplaced(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("uses the sh entrypoint")
	}
	e := start(t)
	v := e.publish(t, filepath.Join(repoRoot(t), "modules", "sysinfo"))
	cfg, agentID := startAgent(t, e, true)
	if j := e.waitFinal(t, e.queue(t, agentID, v, "info", "{}")); j.State != store.JobSucceeded {
		t.Fatalf("first job %s: %s", j.State, j.Error)
	}
	// Replace the cached entrypoint with something else.
	matches, _ := filepath.Glob(filepath.Join(cfg.DataDir, "modules", "sysinfo", "*", "files", "main.sh"))
	if len(matches) != 1 {
		t.Fatalf("cache entries: %v", matches)
	}
	os.WriteFile(matches[0], []byte(`read r; echo '{"type":"result","data":{"pwned":true}}'`), 0o600)
	j := e.waitFinal(t, e.queue(t, agentID, v, "info", "{}"))
	if j.State != store.JobSucceeded || strings.Contains(string(j.Result), "pwned") {
		t.Fatalf("tampered module ran: %s %s %s", j.State, j.Result, j.Error)
	}
}

func TestJobForUnknownModuleVersionIsRejected(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("uses the sh entrypoint")
	}
	e := start(t)
	v := e.publish(t, filepath.Join(repoRoot(t), "modules", "sysinfo"))
	_, agentID := startAgent(t, e, true)
	// A job pinning a different manifest hash than the published module.
	forged := *v
	forged.ManifestHash = make([]byte, 32)
	j := e.waitFinal(t, e.queue(t, agentID, &forged, "info", "{}"))
	if j.State != store.JobRejected || !strings.Contains(j.Error, "does not match") {
		t.Fatalf("job %s: %q", j.State, j.Error)
	}
}
