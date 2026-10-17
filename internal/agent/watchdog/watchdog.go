// Package watchdog keeps the agent service alive and applies staged
// updates, rolling back when the new version does not come up.
package watchdog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/agent/health"
	"github.com/stefanozanarini/open-rmm/internal/agent/svcctl"
	"github.com/stefanozanarini/open-rmm/internal/agent/updater"
)

// Config tunes the watchdog; zero values take the defaults.
type Config struct {
	DataDir    string
	InstallDir string
	// AgentArgs are passed to the agent executable (run -config ...).
	AgentArgs []string

	CheckEvery   time.Duration // default 1m
	StaleAfter   time.Duration // health older than this means hung; default 5m
	ApplyTimeout time.Duration // time for a new version to connect; default 10m
	StopTimeout  time.Duration // default 30s
	// MaxRestarts within an hour before the watchdog stops insisting (the
	// service recovery actions and the scheduled check still apply).
	MaxRestarts int // default 6
}

// Watchdog supervises the agent.
type Watchdog struct {
	cfg      Config
	mgr      svcctl.Manager
	log      *slog.Logger
	now      func() time.Time
	sleep    func(context.Context, time.Duration) bool
	restarts []time.Time
}

// New returns a watchdog.
func New(cfg Config, mgr svcctl.Manager, log *slog.Logger) *Watchdog {
	if cfg.CheckEvery == 0 {
		cfg.CheckEvery = time.Minute
	}
	if cfg.StaleAfter == 0 {
		cfg.StaleAfter = 5 * time.Minute
	}
	if cfg.ApplyTimeout == 0 {
		cfg.ApplyTimeout = 10 * time.Minute
	}
	if cfg.StopTimeout == 0 {
		cfg.StopTimeout = 30 * time.Second
	}
	if cfg.MaxRestarts == 0 {
		cfg.MaxRestarts = 6
	}
	return &Watchdog{cfg: cfg, mgr: mgr, log: log, now: time.Now, sleep: sleepCtx}
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// Run loops until ctx ends.
func (w *Watchdog) Run(ctx context.Context) {
	for {
		w.Tick(ctx)
		if !w.sleep(ctx, w.cfg.CheckEvery) {
			return
		}
	}
}

// Tick performs one supervision round.
func (w *Watchdog) Tick(ctx context.Context) {
	if p, err := updater.ReadPending(w.cfg.DataDir); err == nil {
		w.apply(ctx, p)
		return
	} else if !errors.Is(err, os.ErrNotExist) {
		w.log.Error("pending update unreadable, discarding", "err", err)
		_ = updater.RemovePending(w.cfg.DataDir)
	}
	w.supervise()
}

func (w *Watchdog) canRestart() bool {
	cutoff := w.now().Add(-time.Hour)
	kept := w.restarts[:0]
	for _, t := range w.restarts {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	w.restarts = kept
	return len(w.restarts) < w.cfg.MaxRestarts
}

func (w *Watchdog) supervise() {
	running, err := w.mgr.Running(svcctl.Agent)
	if err != nil {
		w.log.Error("agent service status", "err", err)
		return
	}
	if !running {
		if !w.canRestart() {
			w.log.Error("agent keeps stopping; leaving it to the service recovery and scheduled check")
			return
		}
		w.restarts = append(w.restarts, w.now())
		w.log.Warn("agent service not running, starting it")
		if err := w.mgr.Start(svcctl.Agent); err != nil {
			w.log.Error("start agent", "err", err)
		}
		return
	}
	// The agent refreshes its health file every 30s, connected or not; a
	// stale file means its main loop is stuck.
	h, err := health.Read(w.cfg.DataDir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return // never written yet (first start)
	case err == nil && w.now().Sub(h.Updated) <= w.cfg.StaleAfter:
		return
	}
	if !w.canRestart() {
		return
	}
	w.restarts = append(w.restarts, w.now())
	w.log.Warn("agent unresponsive, restarting", "last_health", h.Updated)
	if err := w.mgr.Stop(svcctl.Agent, w.cfg.StopTimeout); err != nil {
		w.log.Error("stop agent", "err", err)
	}
	if err := w.mgr.Start(svcctl.Agent); err != nil {
		w.log.Error("start agent", "err", err)
	}
}

func fileSHA256(p string) (string, error) {
	f, err := os.Open(p) // #nosec G304 -- validated to be inside the versions directory
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// inVersions reports whether p is an executable inside versions/<x>/.
func (w *Watchdog) inVersions(p string) bool {
	base := filepath.Clean(updater.VersionsDir(w.cfg.InstallDir)) + string(filepath.Separator)
	clean := filepath.Clean(p)
	return strings.HasPrefix(clean, base) && filepath.Dir(filepath.Dir(clean))+string(filepath.Separator) == base
}

func (w *Watchdog) apply(ctx context.Context, p *updater.Pending) {
	log := w.log.With("version", p.Version)
	finish := func(applied bool, reason string) {
		if !applied {
			_ = updater.MarkFailed(w.cfg.DataDir, p.Version, reason)
		}
		if err := updater.WriteResult(w.cfg.DataDir, updater.Result{Version: p.Version, Applied: applied, Error: reason, At: w.now()}); err != nil {
			log.Error("write update result", "err", err)
		}
		if err := updater.RemovePending(w.cfg.DataDir); err != nil {
			log.Error("remove pending update", "err", err)
		}
	}
	// Re-check what is about to run: the staged files must be in the
	// versions directory and unchanged since the agent verified them.
	if !w.inVersions(p.AgentExe) || !w.inVersions(p.WatchdogExe) {
		finish(false, "staged files outside the versions directory")
		return
	}
	if sum, err := fileSHA256(p.AgentExe); err != nil || sum != p.AgentSHA256 {
		finish(false, "staged agent executable missing or modified")
		return
	}
	prev, err := w.mgr.Binary(svcctl.Agent)
	if err != nil {
		finish(false, "cannot read the current agent executable: "+err.Error())
		return
	}
	if filepath.Clean(prev) == filepath.Clean(p.AgentExe) {
		finish(true, "")
		return
	}
	log.Info("switching agent to new version", "from", prev, "to", p.AgentExe)
	switchedAt := w.now()
	if err := w.switchTo(p.AgentExe); err != nil {
		log.Error("switch failed, rolling back", "err", err)
		w.rollback(prev)
		finish(false, "switch: "+err.Error())
		return
	}
	deadline := switchedAt.Add(w.cfg.ApplyTimeout)
	for w.now().Before(deadline) {
		if !w.sleep(ctx, 5*time.Second) {
			return // stopping: the pending file stays, the next run resumes
		}
		h, err := health.Read(w.cfg.DataDir)
		if err == nil && h.Connected && h.Version == p.Version && h.Updated.After(switchedAt) {
			log.Info("new agent version is connected")
			finish(true, "")
			return
		}
	}
	log.Error("new version did not connect in time, rolling back", "timeout", w.cfg.ApplyTimeout)
	w.rollback(prev)
	finish(false, fmt.Sprintf("version %s did not connect to the console within %s", p.Version, w.cfg.ApplyTimeout))
}

func (w *Watchdog) switchTo(exe string) error {
	if err := w.mgr.Stop(svcctl.Agent, w.cfg.StopTimeout); err != nil {
		return err
	}
	if err := w.mgr.SetBinary(svcctl.Agent, exe, w.cfg.AgentArgs); err != nil {
		return err
	}
	return w.mgr.Start(svcctl.Agent)
}

func (w *Watchdog) rollback(prev string) {
	if err := w.switchTo(prev); err != nil {
		w.log.Error("ROLLBACK FAILED: agent may be down until the scheduled check", "err", err)
	}
}
