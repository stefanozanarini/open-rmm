package watchdog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/agent/health"
	"github.com/stefanozanarini/open-rmm/internal/agent/svcctl"
	"github.com/stefanozanarini/open-rmm/internal/agent/updater"
)

// fakeServices simulates the service manager; onStart lets a test decide
// what the "started process" does (e.g. write its health file).
type fakeServices struct {
	mu      sync.Mutex
	running map[string]bool
	binary  map[string]string
	starts  map[string]int
	onStart func(name, exe string)
}

func newFake() *fakeServices {
	return &fakeServices{running: map[string]bool{}, binary: map[string]string{}, starts: map[string]int{}}
}

func (f *fakeServices) Running(n string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.running[n], nil
}
func (f *fakeServices) Start(n string) error {
	f.mu.Lock()
	f.running[n] = true
	f.starts[n]++
	exe, cb := f.binary[n], f.onStart
	f.mu.Unlock()
	if cb != nil {
		cb(n, exe)
	}
	return nil
}
func (f *fakeServices) Stop(n string, _ time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.running[n] = false
	return nil
}
func (f *fakeServices) Binary(n string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if b, ok := f.binary[n]; ok {
		return b, nil
	}
	return "", errors.New("no binary")
}
func (f *fakeServices) SetBinary(n, exe string, _ []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.binary[n] = exe
	return nil
}

type env struct {
	w       *Watchdog
	svc     *fakeServices
	data    string
	install string
	clock   time.Time
	oldExe  string
	pending updater.Pending
}

func setup(t *testing.T) *env {
	t.Helper()
	e := &env{svc: newFake(), data: t.TempDir(), install: t.TempDir(), clock: time.Date(2026, 10, 17, 10, 0, 0, 0, time.UTC)}
	e.w = New(Config{DataDir: e.data, InstallDir: e.install, ApplyTimeout: time.Minute, StaleAfter: 5 * time.Minute},
		e.svc, slog.New(slog.NewTextHandler(io.Discard, nil)))
	e.w.now = func() time.Time { return e.clock }
	// Fake sleep: advance the clock instead of waiting.
	e.w.sleep = func(ctx context.Context, d time.Duration) bool { e.clock = e.clock.Add(d); return ctx.Err() == nil }
	e.oldExe = filepath.Join(e.install, "versions", "1.0.0", "openrmm-agent")
	e.svc.binary[svcctl.Agent] = e.oldExe
	e.svc.running[svcctl.Agent] = true

	dir := filepath.Join(e.install, "versions", "1.1.0")
	os.MkdirAll(dir, 0o700)
	agent := filepath.Join(dir, "openrmm-agent")
	os.WriteFile(agent, []byte("new agent"), 0o700)
	os.WriteFile(filepath.Join(dir, "openrmm-watchdog"), []byte("new watchdog"), 0o700)
	sum := sha256.Sum256([]byte("new agent"))
	e.pending = updater.Pending{Version: "1.1.0", AgentExe: agent, AgentSHA256: hex.EncodeToString(sum[:]),
		WatchdogExe: filepath.Join(dir, "openrmm-watchdog")}
	return e
}

// agentWrites makes the started process report version and connectivity.
func (e *env) agentWrites(versionFor func(exe string) (string, bool)) {
	e.svc.onStart = func(name, exe string) {
		if name != svcctl.Agent {
			return
		}
		v, connected := versionFor(exe)
		health.Write(e.data, health.Health{Version: v, Connected: connected, Updated: e.clock.Add(time.Second), Started: e.clock})
	}
}

func TestApplySuccess(t *testing.T) {
	e := setup(t)
	e.agentWrites(func(exe string) (string, bool) {
		if exe == e.pending.AgentExe {
			return "1.1.0", true
		}
		return "1.0.0", true
	})
	updater.WritePending(e.data, e.pending)
	e.w.Tick(context.Background())
	if e.svc.binary[svcctl.Agent] != e.pending.AgentExe {
		t.Fatalf("agent runs %s", e.svc.binary[svcctl.Agent])
	}
	r, err := updater.TakeResult(e.data)
	if err != nil || !r.Applied {
		t.Fatalf("result %+v, %v", r, err)
	}
	if _, err := updater.ReadPending(e.data); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("pending not removed")
	}
}

func TestApplyRollsBackWhenNewVersionDoesNotConnect(t *testing.T) {
	e := setup(t)
	e.agentWrites(func(exe string) (string, bool) {
		if exe == e.pending.AgentExe {
			return "1.1.0", false // starts but never reaches the console
		}
		return "1.0.0", true
	})
	updater.WritePending(e.data, e.pending)
	e.w.Tick(context.Background())
	if e.svc.binary[svcctl.Agent] != e.oldExe || !e.svc.running[svcctl.Agent] {
		t.Fatalf("not rolled back: %s running=%v", e.svc.binary[svcctl.Agent], e.svc.running[svcctl.Agent])
	}
	r, _ := updater.TakeResult(e.data)
	if r == nil || r.Applied || r.Error == "" {
		t.Fatalf("result %+v", r)
	}
	if !updater.HasFailed(e.data, "1.1.0") {
		t.Fatal("failed version not recorded: it would be retried forever")
	}
}

func TestApplyRefusesModifiedStagedFile(t *testing.T) {
	e := setup(t)
	os.WriteFile(e.pending.AgentExe, []byte("tampered"), 0o700)
	updater.WritePending(e.data, e.pending)
	e.w.Tick(context.Background())
	if e.svc.binary[svcctl.Agent] != e.oldExe || e.svc.starts[svcctl.Agent] != 0 {
		t.Fatal("modified executable was installed")
	}
	if r, _ := updater.TakeResult(e.data); r == nil || r.Applied {
		t.Fatalf("result %+v", r)
	}
}

func TestApplyRefusesFilesOutsideVersions(t *testing.T) {
	e := setup(t)
	evil := filepath.Join(t.TempDir(), "openrmm-agent")
	os.WriteFile(evil, []byte("new agent"), 0o700)
	e.pending.AgentExe = evil
	updater.WritePending(e.data, e.pending)
	e.w.Tick(context.Background())
	if e.svc.binary[svcctl.Agent] != e.oldExe {
		t.Fatal("executable outside the versions directory was installed")
	}
}

func TestSuperviseStartsStoppedAgentWithLimit(t *testing.T) {
	e := setup(t)
	e.svc.running[svcctl.Agent] = false
	for range 10 {
		e.w.Tick(context.Background())
		e.svc.running[svcctl.Agent] = false // it keeps crashing
		e.clock = e.clock.Add(time.Minute)
	}
	if got := e.svc.starts[svcctl.Agent]; got != e.w.cfg.MaxRestarts {
		t.Fatalf("started %d times, want %d", got, e.w.cfg.MaxRestarts)
	}
	// After an hour it tries again.
	e.clock = e.clock.Add(time.Hour)
	e.w.Tick(context.Background())
	if e.svc.starts[svcctl.Agent] != e.w.cfg.MaxRestarts+1 {
		t.Fatal("restart budget not renewed")
	}
}

func TestSuperviseRestartsHungAgent(t *testing.T) {
	e := setup(t)
	health.Write(e.data, health.Health{Version: "1.0.0", Updated: e.clock, Started: e.clock})
	e.w.Tick(context.Background())
	if e.svc.starts[svcctl.Agent] != 0 {
		t.Fatal("healthy agent restarted")
	}
	e.clock = e.clock.Add(10 * time.Minute)
	e.w.Tick(context.Background())
	if e.svc.starts[svcctl.Agent] != 1 {
		t.Fatal("hung agent not restarted")
	}
}
