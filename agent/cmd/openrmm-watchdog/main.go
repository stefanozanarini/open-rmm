// Command openrmm-watchdog keeps the agent service running and applies the
// updates staged by the agent, rolling back if a new version does not come
// up.
//
//	openrmm-watchdog run [-config path]       run (as a service on Windows, under systemd on Linux)
//	openrmm-watchdog install [-config path]   install the Windows service and the scheduled health check
//	openrmm-watchdog uninstall
//	openrmm-watchdog msi-uninstall [-config path]  cleanup run by the MSI on removal
//	openrmm-watchdog version
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/stefanozanarini/open-rmm/internal/agent/config"
	"github.com/stefanozanarini/open-rmm/internal/agent/svcctl"
	"github.com/stefanozanarini/open-rmm/internal/agent/watchdog"
	"github.com/stefanozanarini/open-rmm/internal/agent/winsvc"
)

var version = "0.0.0-dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "openrmm-watchdog:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cmd := "run"
	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		cmd, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	cfgPath := fs.String("config", config.DefaultConfigPath(), "agent configuration file")
	asService := fs.Bool("service", false, "run as a Windows service (set in the service command line)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch cmd {
	case "run":
		// -service is explicit, as automatic detection is a heuristic.
		if (*asService && runtime.GOOS == "windows") || winsvc.IsService() {
			return winsvc.Run(svcctl.Watchdog, func(ctx context.Context, log *slog.Logger) error {
				return runWatchdog(ctx, *cfgPath, log)
			})
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return runWatchdog(ctx, *cfgPath, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	case "install":
		if err := winsvc.Install(svcctl.Watchdog, "open-rmm watchdog", "Keeps the open-rmm agent running and applies its updates",
			"run", "-service", "-config", *cfgPath); err != nil {
			return err
		}
		return winsvc.InstallHealthTask()
	case "uninstall":
		_ = winsvc.UninstallHealthTask()
		return winsvc.Uninstall(svcctl.Watchdog)
	case "msi-uninstall":
		return msiUninstall(*cfgPath)
	case "version":
		fmt.Println(version)
		return nil
	default:
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func runWatchdog(ctx context.Context, cfgPath string, log *slog.Logger) error {
	// The watchdog only needs the data and install paths: with an incomplete
	// configuration (agent not configured yet) it keeps working with the
	// defaults rather than exiting.
	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Warn("agent configuration incomplete, using default paths", "err", err)
		cfg = &config.Config{DataDir: config.DefaultDataDir(), InstallDir: config.DefaultInstallDir()}
	}
	log.Info("watchdog starting", "version", version)
	if winsvc.IsService() {
		for _, name := range []string{svcctl.Watchdog, svcctl.Agent} {
			if err := winsvc.Ensure(name); err != nil {
				log.Warn("service settings", "service", name, "err", err)
			}
		}
		if err := winsvc.InstallHealthTask(); err != nil {
			log.Warn("scheduled health check", "err", err)
		}
	}
	watchdog.New(watchdog.Config{
		DataDir: cfg.DataDir, InstallDir: cfg.InstallDir, AgentArgs: serviceArgs(cfgPath),
	}, svcctl.New(), log).Run(ctx)
	return nil
}

// msiUninstall removes what the MSI does not track: the scheduled task, the
// versions installed by automatic updates, and the agent state (including
// its private key). The MSI runs it after deleting the services, and not
// during upgrades.
//
// Paths are not taken from the configuration file, which could have been
// tampered with to point elsewhere: the versions directory is the parent of
// this executable's own directory, and only the default data directory is
// removed.
func msiUninstall(_ string) error {
	_ = winsvc.UninstallHealthTask()
	self, err := os.Executable()
	if err != nil {
		return err
	}
	selfDir := filepath.Dir(self)
	versions := filepath.Dir(selfDir)
	if filepath.Base(versions) != "versions" || filepath.Base(filepath.Dir(versions)) != "open-rmm" {
		return fmt.Errorf("%s is not an open-rmm installation, nothing removed", selfDir)
	}
	entries, _ := os.ReadDir(versions)
	for _, e := range entries {
		dir := filepath.Join(versions, e.Name())
		// The MSI removes its own files; this one is still running.
		if e.IsDir() && filepath.Clean(dir) != filepath.Clean(selfDir) {
			_ = os.RemoveAll(dir)
		}
	}
	return os.RemoveAll(config.DefaultDataDir())
}

// serviceArgs is the command line of the services after an executable
// switch; it must match what the installer registers.
func serviceArgs(cfgPath string) []string {
	if runtime.GOOS == "windows" {
		return []string{"run", "-service", "-config", cfgPath}
	}
	return []string{"run", "-config", cfgPath}
}
