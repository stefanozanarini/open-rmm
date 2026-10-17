package updater

import (
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/agent/svcctl"
	"github.com/stefanozanarini/open-rmm/internal/release"
)

// UpdateWatchdog is run by a freshly applied agent: when the agent executable
// lives in versions/<v>/ and the watchdog service still runs an older one,
// it switches the watchdog to versions/<v>/ too. The two never switch at the
// same time, so one of them is always there to repair the other.
func UpdateWatchdog(mgr svcctl.Manager, installDir string, watchdogArgs []string, log *slog.Logger) {
	self, err := os.Executable()
	if err != nil {
		return
	}
	self, _ = filepath.EvalSymlinks(self)
	dir := filepath.Dir(self)
	if filepath.Dir(dir) != filepath.Clean(VersionsDir(installDir)) {
		return // not an installed version (development run)
	}
	target := filepath.Join(dir, release.WatchdogFile(runtime.GOOS))
	if _, err := os.Stat(target); err != nil {
		return
	}
	cur, err := mgr.Binary(svcctl.Watchdog)
	if err != nil || filepath.Clean(cur) == filepath.Clean(target) {
		return
	}
	log.Info("updating the watchdog", "from", cur, "to", target)
	switchTo := func(exe string) error {
		if err := mgr.Stop(svcctl.Watchdog, 30*time.Second); err != nil {
			return err
		}
		if err := mgr.SetBinary(svcctl.Watchdog, exe, watchdogArgs); err != nil {
			return err
		}
		return mgr.Start(svcctl.Watchdog)
	}
	ok := switchTo(target) == nil
	if ok {
		time.Sleep(30 * time.Second)
		ok, _ = mgr.Running(svcctl.Watchdog)
	}
	if !ok {
		log.Error("new watchdog did not start, rolling back", "to", cur)
		if err := switchTo(cur); err != nil {
			log.Error("watchdog rollback failed", "err", err)
		}
	}
}
