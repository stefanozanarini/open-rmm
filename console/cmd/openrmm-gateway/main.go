// Command openrmm-gateway serves the agents endpoint (the only component
// meant to be exposed to the internet). TLS is terminated here, never on a
// proxy in front of it, so client certificates are verified by the gateway.
//
// Configuration (environment):
//
//	OPENRMM_DATABASE_URL     PostgreSQL connection string
//	OPENRMM_LISTEN           listen address (default :8443)
//	OPENRMM_TLS_CERT         gateway certificate chain (gateway.crt)
//	OPENRMM_TLS_KEY          gateway key (gateway.key)
//	OPENRMM_AGENTS_CA_CERT   agents CA certificate (agents-ca.crt)
//	OPENRMM_AGENTS_CA_KEY    agents CA key (agents-ca.key)
//
// "openrmm-gateway healthcheck" exits 0 if the listener accepts TCP
// connections; it is meant for container health checks, where the image has
// no shell or curl.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/console/gateway"
	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/pki"
	"github.com/stefanozanarini/open-rmm/internal/tlsconf"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck())
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func healthcheck() int {
	addr := env("OPENRMM_LISTEN", ":8443")
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 1
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	c, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 3*time.Second)
	if err != nil {
		return 1
	}
	_ = c.Close()
	return 0
}

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func mustEnv(name string) (string, error) {
	v := os.Getenv(name)
	if v == "" {
		return "", fmt.Errorf("%s is required", name)
	}
	return v, nil
}

func readFiles(names ...string) ([][]byte, error) {
	var out [][]byte
	for _, n := range names {
		path, err := mustEnv(n)
		if err != nil {
			return nil, err
		}
		b, err := os.ReadFile(path) // #nosec G304 -- path from the operator-controlled environment
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

func run(log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	files, err := readFiles("OPENRMM_TLS_CERT", "OPENRMM_TLS_KEY", "OPENRMM_AGENTS_CA_CERT", "OPENRMM_AGENTS_CA_KEY")
	if err != nil {
		return err
	}
	srvCerts, err := pki.ParseCertsPEM(files[0])
	if err != nil {
		return fmt.Errorf("gateway certificate: %w", err)
	}
	srvKey, err := pki.ParseKeyPEM(files[1])
	if err != nil {
		return fmt.Errorf("gateway key: %w", err)
	}
	ca, err := pki.LoadCA(files[2], files[3])
	if err != nil {
		return fmt.Errorf("agents CA: %w", err)
	}

	dbURL, err := mustEnv("OPENRMM_DATABASE_URL")
	if err != nil {
		return err
	}
	db, err := store.OpenPostgres(ctx, dbURL)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		return err
	}

	gw, err := gateway.New(gateway.Config{Store: db, AgentsCA: ca, Logger: log})
	if err != nil {
		return err
	}
	gs := gw.GRPCServer(tlsconf.Server(srvCerts[0], srvCerts[1:], srvKey, ca.Cert))
	// Wakes agent sessions when jobs are queued (PostgreSQL LISTEN/NOTIFY).
	go gw.Run(ctx)

	lis, err := net.Listen("tcp", env("OPENRMM_LISTEN", ":8443"))
	if err != nil {
		return err
	}
	log.Info("gateway listening", "addr", lis.Addr().String())
	errCh := make(chan error, 1)
	go func() { errCh <- gs.Serve(lis) }()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	stopped := make(chan struct{})
	go func() { gs.GracefulStop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(15 * time.Second):
		gs.Stop()
	}
	if err := <-errCh; err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}
