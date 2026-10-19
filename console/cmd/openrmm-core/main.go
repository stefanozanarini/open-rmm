// Command openrmm-core is the internal part of the agents endpoint: agent
// sessions, enrollment and certificate issuance, job dispatch, module and
// release downloads. It holds the database credentials and the agents CA
// key, and it is never exposed: it opens the tunnels to the gateway (DMZ)
// itself, so no connection from the DMZ to the internal network is needed.
//
// Configuration (environment):
//
//	OPENRMM_DATABASE_URL       PostgreSQL connection string
//	OPENRMM_AGENTS_CA_CERT     agents CA certificate (agents-ca.crt)
//	OPENRMM_AGENTS_CA_KEY      agents CA key (agents-ca.key)
//	OPENRMM_ROOT_CA            root CA certificate, to verify the gateway (root-ca.crt)
//	OPENRMM_CORE_CERT          core tunnel certificate chain (core.crt)
//	OPENRMM_CORE_KEY           core tunnel key (core.key)
//	OPENRMM_GATEWAY_TUNNEL     gateway tunnel address, host:port (e.g. gateway:8444)
//	OPENRMM_GATEWAY_NAME       DNS name in the gateway certificate (default: host of OPENRMM_GATEWAY_TUNNEL)
//	OPENRMM_HEALTH_LISTEN      local health endpoint (default 127.0.0.1:8090)
//
// "openrmm-core healthcheck" exits 0 when a tunnel to the gateway is open.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/console/gateway"
	"github.com/stefanozanarini/open-rmm/internal/console/relay"
	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/pki"
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

func readEnvFile(name string) ([]byte, error) {
	path, err := mustEnv(name)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(path) // #nosec G304,G703 -- path from the operator-controlled environment
}

func healthcheck() int {
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://" + env("OPENRMM_HEALTH_LISTEN", "127.0.0.1:8090") + "/healthz")
	if err != nil {
		return 1
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return 1
	}
	return 0
}

func run(log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	caCert, err := readEnvFile("OPENRMM_AGENTS_CA_CERT")
	if err != nil {
		return err
	}
	caKey, err := readEnvFile("OPENRMM_AGENTS_CA_KEY")
	if err != nil {
		return err
	}
	ca, err := pki.LoadCA(caCert, caKey)
	if err != nil {
		return fmt.Errorf("agents CA: %w", err)
	}
	rootPEM, err := readEnvFile("OPENRMM_ROOT_CA")
	if err != nil {
		return err
	}
	roots, err := pki.ParseCertsPEM(rootPEM)
	if err != nil {
		return fmt.Errorf("root CA: %w", err)
	}
	coreCertPEM, err := readEnvFile("OPENRMM_CORE_CERT")
	if err != nil {
		return err
	}
	coreKeyPEM, err := readEnvFile("OPENRMM_CORE_KEY")
	if err != nil {
		return err
	}
	coreCert, err := tls.X509KeyPair(coreCertPEM, coreKeyPEM)
	if err != nil {
		return fmt.Errorf("core certificate: %w", err)
	}
	target, err := mustEnv("OPENRMM_GATEWAY_TUNNEL")
	if err != nil {
		return err
	}
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("OPENRMM_GATEWAY_TUNNEL: %w", err)
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
	// Wakes agent sessions when jobs are queued (PostgreSQL LISTEN/NOTIFY).
	go gw.Run(ctx)

	d := &relay.Dialer{Target: target, Log: log,
		TLS: relay.CoreTLS(env("OPENRMM_GATEWAY_NAME", host), roots[0], coreCert)}
	ts := gw.TunnelGRPCServer()
	go func() {
		if err := ts.Serve(d); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Error("tunnel server", "err", err)
		}
	}()
	go d.Run(ctx)

	health := &http.Server{
		Addr:              env("OPENRMM_HEALTH_LISTEN", "127.0.0.1:8090"),
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if d.Up() == 0 {
				http.Error(w, "no tunnel to the gateway", http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}),
	}
	go func() { _ = health.ListenAndServe() }()

	log.Info("core started", "gateway_tunnel", target)
	<-ctx.Done()
	log.Info("shutting down")
	_ = health.Close()
	stopped := make(chan struct{})
	go func() { ts.GracefulStop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(15 * time.Second):
		ts.Stop()
	}
	return nil
}
