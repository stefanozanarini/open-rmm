// Command openrmm-agent is the open-rmm endpoint agent core.
//
//	openrmm-agent run [-config path]        run in the foreground (or as a service)
//	openrmm-agent install [-config path]    install the Windows service (development; the MSI does this)
//	openrmm-agent uninstall                 remove the Windows service
//	openrmm-agent version
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/stefanozanarini/open-rmm/internal/agent/client"
	"github.com/stefanozanarini/open-rmm/internal/agent/config"
	"github.com/stefanozanarini/open-rmm/internal/agent/svcctl"
	"github.com/stefanozanarini/open-rmm/internal/agent/winsvc"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "0.0.0-dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "openrmm-agent:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cmd := "run"
	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		cmd, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	cfgPath := fs.String("config", config.DefaultConfigPath(), "configuration file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch cmd {
	case "run":
		if winsvc.IsService() {
			return winsvc.Run(svcctl.Agent, func(ctx context.Context, log *slog.Logger) error {
				return runAgent(ctx, *cfgPath, log, true)
			})
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		// Under systemd (INVOCATION_ID is set) the agent manages the
		// watchdog unit too.
		managed := os.Getenv("INVOCATION_ID") != ""
		return runAgent(ctx, *cfgPath, slog.New(slog.NewTextHandler(os.Stderr, nil)), managed)
	case "install":
		return winsvc.Install(svcctl.Agent, "open-rmm agent", "open-rmm endpoint management agent", "run", "-config", *cfgPath)
	case "uninstall":
		return winsvc.Uninstall(svcctl.Agent)
	case "version":
		fmt.Println(version)
		return nil
	default:
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func runAgent(ctx context.Context, cfgPath string, log *slog.Logger, managed bool) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	log.Info("starting", "version", version, "server", cfg.Server)
	c := client.New(cfg, version, log)
	if managed {
		c.Services, c.ConfigPath = svcctl.New(), cfgPath
	}
	return c.Run(ctx)
}
