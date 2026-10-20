// Command openrmm-builder holds the Authenticode signing key, encrypted with
// a passphrase that is asked for each operation and never stored, and
// builds signed agent installers for the console. It listens on a Unix
// socket shared only with the web console and needs outbound HTTP only for
// the RFC 3161 timestamp server.
//
// Configuration (environment):
//
//	OPENRMM_BUILDER_DIR      state: encrypted keys and certificates (default /var/lib/openrmm-builder)
//	OPENRMM_BUILDER_SOCKET   socket path (default /run/openrmm-builder/builder.sock)
//	OPENRMM_BUILDER_WXS      MSI source (default /usr/share/openrmm/openrmm-agent.wxs)
//
// "openrmm-builder healthcheck" exits 0 when the socket accepts connections.
package main

import (
	"context"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"google.golang.org/grpc"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/open-rmm/internal/builder"
)

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func main() {
	sock := env("OPENRMM_BUILDER_SOCKET", "/run/openrmm-builder/builder.sock")
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		c, err := net.DialTimeout("unix", sock, 3*time.Second)
		if err != nil {
			os.Exit(1)
		}
		_ = c.Close()
		os.Exit(0)
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log, sock); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger, sock string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	dir := env("OPENRMM_BUILDER_DIR", "/var/lib/openrmm-builder")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	svc := &builder.Service{Dir: dir, WXS: env("OPENRMM_BUILDER_WXS", "/usr/share/openrmm/openrmm-agent.wxs"), Log: log}
	_ = os.Remove(sock)
	if err := os.MkdirAll(filepath.Dir(sock), 0o750); err != nil {
		return err
	}
	lis, err := net.Listen("unix", sock)
	if err != nil {
		return err
	}
	// Owner only: the console container runs as the same user.
	if err := os.Chmod(sock, 0o600); err != nil {
		return err
	}
	gs := grpc.NewServer(grpc.MaxRecvMsgSize(2*builder.MaxExecutable + 1<<20))
	openrmmv1.RegisterBuilderServiceServer(gs, svc)
	log.Info("builder listening", "socket", sock, "dir", dir)
	go func() { <-ctx.Done(); gs.GracefulStop() }()
	return gs.Serve(lis)
}
