package updater

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/open-rmm/internal/agent/config"
	"github.com/stefanozanarini/open-rmm/internal/agent/secfile"
	"github.com/stefanozanarini/open-rmm/internal/release"
)

// Session is the live connection: it downloads releases and reports status.
type Session interface {
	FetchRelease(ctx context.Context, version, platform string) (map[string][]byte, error)
	SendUpdateStatus(*openrmmv1.UpdateStatus)
}

// Updater handles release offers.
type Updater struct {
	cfg      *config.Config
	running  release.Version
	platform string
	log      *slog.Logger

	mu   sync.Mutex
	busy bool
}

// New returns an updater for an agent running runningVersion.
func New(cfg *config.Config, runningVersion string, log *slog.Logger) *Updater {
	return &Updater{cfg: cfg, running: release.ParseRunning(runningVersion),
		platform: runtime.GOOS + "/" + runtime.GOARCH, log: log}
}

// VersionsDir is where releases are installed.
func VersionsDir(installDir string) string { return filepath.Join(installDir, "versions") }

// Offer handles an AgentUpdateOffer. It returns quickly; the download runs
// in the background.
func (u *Updater) Offer(ctx context.Context, s Session, env *openrmmv1.SignedEnvelope) {
	u.mu.Lock()
	if u.busy {
		u.mu.Unlock()
		return
	}
	u.busy = true
	u.mu.Unlock()
	go func() {
		defer func() { u.mu.Lock(); u.busy = false; u.mu.Unlock() }()
		if st := u.install(ctx, s, env); st != nil {
			s.SendUpdateStatus(st)
		}
	}()
}

func rejected(version, format string, args ...any) *openrmmv1.UpdateStatus {
	return &openrmmv1.UpdateStatus{Version: version, State: openrmmv1.UpdateStatus_STATE_REJECTED, Error: fmt.Sprintf(format, args...)}
}

func (u *Updater) install(ctx context.Context, s Session, env *openrmmv1.SignedEnvelope) *openrmmv1.UpdateStatus {
	if u.cfg.ReleaseKeyring().Len() == 0 {
		return rejected("", "no release signing keys configured on this endpoint")
	}
	m, err := release.Verify(u.cfg.ReleaseKeyring(), env.GetKeyId(), env.GetPayload(), env.GetSignature())
	if err != nil {
		u.log.Warn("release rejected", "err", err)
		return rejected("", "%v", err)
	}
	v, _ := release.ParseVersion(m.Version)
	switch {
	case m.Platform != u.platform:
		return rejected(m.Version, "release is for %s, this endpoint is %s", m.Platform, u.platform)
	case !u.running.Less(v):
		// Never downgrade, even with a valid signature: old versions may
		// have known vulnerabilities.
		return nil
	case HasFailed(u.cfg.DataDir, m.Version):
		return nil // rolled back before: wait for a newer release
	}
	if p, err := ReadPending(u.cfg.DataDir); err == nil && p.Version == m.Version {
		return nil // already staged, waiting for the watchdog
	}
	log := u.log.With("version", m.Version)
	log.Info("downloading agent release")
	s.SendUpdateStatus(&openrmmv1.UpdateStatus{Version: m.Version, State: openrmmv1.UpdateStatus_STATE_DOWNLOADING})

	goos := runtime.GOOS
	agentF, _ := m.File(release.AgentFile(goos))
	wdF, _ := m.File(release.WatchdogFile(goos))
	dir := filepath.Join(VersionsDir(u.cfg.InstallDir), m.Version)
	if err := checkInstalled(dir, agentF, wdF); err != nil {
		files, err := s.FetchRelease(ctx, m.Version, m.Platform)
		if err != nil {
			log.Warn("release download failed", "err", err)
			return nil // retried at the next offer
		}
		for _, f := range []release.File{agentF, wdF} {
			if err := f.CheckFile(files[f.Name]); err != nil {
				return rejected(m.Version, "%v", err)
			}
		}
		if err := writeVersion(VersionsDir(u.cfg.InstallDir), m.Version, files); err != nil {
			return rejected(m.Version, "install: %v", err)
		}
	}
	p := Pending{Version: m.Version, AgentExe: filepath.Join(dir, agentF.Name), AgentSHA256: agentF.SHA256,
		WatchdogExe: filepath.Join(dir, wdF.Name), WatchdogSHA256: wdF.SHA256, StagedAt: time.Now()}
	if err := WritePending(u.cfg.DataDir, p); err != nil {
		return rejected(m.Version, "stage: %v", err)
	}
	log.Info("agent release staged, waiting for the watchdog")
	return &openrmmv1.UpdateStatus{Version: m.Version, State: openrmmv1.UpdateStatus_STATE_STAGED}
}

func checkInstalled(dir string, files ...release.File) error {
	for _, f := range files {
		data, err := os.ReadFile(filepath.Join(dir, f.Name)) // #nosec G304 -- install dir, file name from the signed manifest
		if err != nil {
			return err
		}
		if err := f.CheckFile(data); err != nil {
			return err
		}
	}
	return nil
}

// writeVersion installs the files in versions/<version> atomically.
func writeVersion(versionsDir, version string, files map[string][]byte) error {
	if err := secfile.EnsureDir(versionsDir); err != nil {
		return err
	}
	final := filepath.Join(versionsDir, version)
	tmp, err := os.MkdirTemp(versionsDir, ".staging-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(tmp, name), data, 0o700); err != nil { // #nosec G306 -- executables, admin-only directory
			return err
		}
	}
	if err := os.RemoveAll(final); err != nil {
		return err
	}
	return os.Rename(tmp, final)
}

// ReportResult sends the outcome of the last update applied by the watchdog.
func (u *Updater) ReportResult(s Session) {
	r, err := TakeResult(u.cfg.DataDir)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			u.log.Warn("update result unreadable", "err", err)
		}
		return
	}
	st := &openrmmv1.UpdateStatus{Version: r.Version, State: openrmmv1.UpdateStatus_STATE_APPLIED}
	if !r.Applied {
		st.State, st.Error = openrmmv1.UpdateStatus_STATE_ROLLED_BACK, r.Error
	}
	s.SendUpdateStatus(st)
}
