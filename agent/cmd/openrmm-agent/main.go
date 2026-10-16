// Command openrmm-agent is the open-rmm endpoint agent core.
//
//	openrmm-agent run [-config path]        run in the foreground (or as a service)
//	openrmm-agent install [-config path]    install the Windows service
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
		if isService() {
			return runService(*cfgPath)
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return runAgent(ctx, *cfgPath, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	case "install":
		return installService(*cfgPath)
	case "uninstall":
		return uninstallService()
	case "version":
		fmt.Println(version)
		return nil
	default:
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func runAgent(ctx context.Context, cfgPath string, log *slog.Logger) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	log.Info("starting", "version", version, "server", cfg.Server)
	return client.New(cfg, version, log).Run(ctx)
}
