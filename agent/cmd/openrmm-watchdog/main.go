// Command openrmm-watchdog keeps the agent service running and applies the
// updates staged by the agent, rolling back if a new version does not come
// up.
//
//	openrmm-watchdog run [-config path]       run (as a service on Windows, under systemd on Linux)
//	openrmm-watchdog install [-config path]   install the Windows service and the scheduled health check
//	openrmm-watchdog uninstall
//	openrmm-watchdog version
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
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
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch cmd {
	case "run":
		if winsvc.IsService() {
			return winsvc.Run(svcctl.Watchdog, func(ctx context.Context, log *slog.Logger) error {
				return runWatchdog(ctx, *cfgPath, log)
			})
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return runWatchdog(ctx, *cfgPath, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	case "install":
		if err := winsvc.Install(svcctl.Watchdog, "open-rmm watchdog", "Keeps the open-rmm agent running and applies its updates",
			"run", "-config", *cfgPath); err != nil {
			return err
		}
		return winsvc.InstallHealthTask()
	case "uninstall":
		_ = winsvc.UninstallHealthTask()
		return winsvc.Uninstall(svcctl.Watchdog)
	case "version":
		fmt.Println(version)
		return nil
	default:
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func runWatchdog(ctx context.Context, cfgPath string, log *slog.Logger) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	log.Info("watchdog starting", "version", version)
	watchdog.New(watchdog.Config{
		DataDir: cfg.DataDir, InstallDir: cfg.InstallDir, AgentArgs: []string{"run", "-config", cfgPath},
	}, svcctl.New(), log).Run(ctx)
	return nil
}
