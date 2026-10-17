package e2e

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/agent/updater"
	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/release"
	"github.com/stefanozanarini/open-rmm/internal/signing"
)

// publishRelease signs fake executables as release version and publishes it.
func (e *env) publishRelease(t *testing.T, s *signing.Signer, version string, tamper bool) {
	t.Helper()
	goos := runtime.GOOS
	files := map[string][]byte{
		release.AgentFile(goos):    []byte("agent " + version),
		release.WatchdogFile(goos): []byte("watchdog " + version),
	}
	m := &release.Manifest{Version: version, Platform: platform(), ReleasedAt: time.Now()}
	for n, d := range files {
		m.Files = append(m.Files, release.HashFile(n, d))
	}
	raw, sig, err := release.Sign(s, m)
	if err != nil {
		t.Fatal(err)
	}
	if tamper {
		files[release.AgentFile(goos)] = []byte("evil")
	}
	if err := e.store.PutRelease(context.Background(), store.Release{Version: version, Platform: platform(),
		KeyID: s.KeyID(), Manifest: raw, Signature: sig, Files: files}); err != nil {
		t.Fatal(err)
	}
}

func (e *env) target(t *testing.T, ring, version string) {
	t.Helper()
	if err := e.store.SetReleaseTarget(context.Background(), store.ReleaseTarget{TenantID: e.tenant, Ring: ring,
		Platform: platform(), Version: version, UpdatedBy: "test"}); err != nil {
		t.Fatal(err)
	}
}

func (e *env) waitUpdateState(t *testing.T, agentID, state string) store.Agent {
	t.Helper()
	var a store.Agent
	waitFor(t, func() bool {
		a, _ = e.store.GetAgent(context.Background(), e.tenant, agentID)
		return a.Update.State == state
	})
	return a
}

func TestAgentStagesTargetedRelease(t *testing.T) {
	e := start(t)
	cfg, agentID := startAgent(t, e, true)
	e.publishRelease(t, e.releaseSigner, "1.0.0", false)
	// Setting the target wakes the connected agent: no reconnection needed.
	e.target(t, store.RingBroad, "1.0.0")
	a := e.waitUpdateState(t, agentID, "staged")
	if a.Update.Version != "1.0.0" {
		t.Fatalf("update = %+v", a.Update)
	}
	p, err := updater.ReadPending(cfg.DataDir)
	if err != nil || p.Version != "1.0.0" {
		t.Fatalf("pending = %+v, %v", p, err)
	}
	data, err := os.ReadFile(p.AgentExe)
	if err != nil || string(data) != "agent 1.0.0" {
		t.Fatalf("staged agent = %q, %v", data, err)
	}
	if filepath.Dir(p.AgentExe) != filepath.Join(cfg.InstallDir, "versions", "1.0.0") {
		t.Fatalf("staged in %s", p.AgentExe)
	}
}

func TestReleaseSignedByUntrustedKeyIsRejected(t *testing.T) {
	e := start(t)
	cfg, agentID := startAgent(t, e, true)
	e.publishRelease(t, newSigner(t), "1.0.0", false)
	e.target(t, store.RingBroad, "1.0.0")
	e.waitUpdateState(t, agentID, "rejected")
	if _, err := updater.ReadPending(cfg.DataDir); err == nil {
		t.Fatal("untrusted release staged")
	}
}

func TestTamperedReleaseFileIsRejected(t *testing.T) {
	e := start(t)
	cfg, agentID := startAgent(t, e, true)
	e.publishRelease(t, e.releaseSigner, "1.0.0", true)
	e.target(t, store.RingBroad, "1.0.0")
	a := e.waitUpdateState(t, agentID, "rejected")
	if _, err := updater.ReadPending(cfg.DataDir); err == nil {
		t.Fatalf("tampered release staged (%s)", a.Update.Error)
	}
}

func TestOnlyTargetedRingIsOffered(t *testing.T) {
	e := start(t)
	cfg, agentID := startAgent(t, e, true) // ring broad by default
	e.publishRelease(t, e.releaseSigner, "1.0.0", false)
	e.target(t, store.RingPilot, "1.0.0")
	time.Sleep(500 * time.Millisecond)
	if a, _ := e.store.GetAgent(context.Background(), e.tenant, agentID); a.Update.State != "" {
		t.Fatalf("broad agent got the pilot release: %+v", a.Update)
	}
	// Moving the agent to the pilot ring delivers it.
	e.store.SetAgentRing(context.Background(), e.tenant, agentID, store.RingPilot)
	e.target(t, store.RingPilot, "1.0.0") // re-notify
	e.waitUpdateState(t, agentID, "staged")
	if _, err := updater.ReadPending(cfg.DataDir); err != nil {
		t.Fatal(err)
	}
}

func TestNoDowngrade(t *testing.T) {
	e := start(t)
	cfg := e.agentConfig(t, e.tokenWith(t, 1, true))
	runAgentVersion(t, cfg, "2.0.0")
	agentID := e.onlyAgent(t).ID
	e.publishRelease(t, e.releaseSigner, "1.5.0", false)
	e.target(t, store.RingBroad, "1.5.0")
	time.Sleep(500 * time.Millisecond)
	if a, _ := e.store.GetAgent(context.Background(), e.tenant, agentID); a.Update.State != "" {
		t.Fatalf("older release offered to a newer agent: %+v", a.Update)
	}
	if _, err := updater.ReadPending(cfg.DataDir); err == nil {
		t.Fatal("older release staged")
	}
}
