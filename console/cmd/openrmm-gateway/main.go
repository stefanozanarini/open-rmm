// Command openrmm-gateway is the internet-facing agents endpoint, meant for
// a DMZ. It terminates the agents' mTLS (verifying their certificates with
// the public agents CA certificate) and relays the allowed calls, as opaque
// frames, over the tunnels opened by openrmm-core. It has no database
// credentials and no CA private key.
//
// Configuration (environment):
//
//	OPENRMM_LISTEN           agents listener (default :8443)
//	OPENRMM_TUNNEL_LISTEN    tunnel listener for openrmm-core (default :8444);
//	                         allow it only from the internal network
//	OPENRMM_TLS_CERT         gateway certificate chain (gateway.crt)
//	OPENRMM_TLS_KEY          gateway key (gateway.key)
//	OPENRMM_AGENTS_CA_CERT   agents CA certificate (agents-ca.crt), public part only
//
// "openrmm-gateway healthcheck" exits 0 if the agents listener accepts TCP
// connections.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc/credentials"

	"github.com/stefanozanarini/open-rmm/internal/console/relay"
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

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func healthcheck() int {
	_, port, err := net.SplitHostPort(env("OPENRMM_LISTEN", ":8443"))
	if err != nil {
		return 1
	}
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", port), 3*time.Second)
	if err != nil {
		return 1
	}
	_ = c.Close()
	return 0
}

func readEnvFile(name string) ([]byte, error) {
	path := os.Getenv(name)
	if path == "" {
		return nil, fmt.Errorf("%s is required", name)
	}
	return os.ReadFile(path) // #nosec G304,G703 -- path from the operator-controlled environment
}

func run(log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	certPEM, err := readEnvFile("OPENRMM_TLS_CERT")
	if err != nil {
		return err
	}
	keyPEM, err := readEnvFile("OPENRMM_TLS_KEY")
	if err != nil {
		return err
	}
	caPEM, err := readEnvFile("OPENRMM_AGENTS_CA_CERT")
	if err != nil {
		return err
	}
	certs, err := pki.ParseCertsPEM(certPEM)
	if err != nil {
		return fmt.Errorf("gateway certificate: %w", err)
	}
	key, err := pki.ParseKeyPEM(keyPEM)
	if err != nil {
		return fmt.Errorf("gateway key: %w", err)
	}
	cas, err := pki.ParseCertsPEM(caPEM)
	if err != nil {
		return fmt.Errorf("agents CA: %w", err)
	}
	agentsCA := cas[0]
	agentTLS := tlsconf.Server(certs[0], certs[1:], key, agentsCA)

	pool := relay.NewTunnelPool(log)
	rawTunnel, err := net.Listen("tcp", env("OPENRMM_TUNNEL_LISTEN", ":8444"))
	if err != nil {
		return err
	}
	go func() {
		if err := pool.Serve(ctx, tls.NewListener(rawTunnel, relay.TunnelTLS(agentTLS.Certificates[0], agentsCA))); err != nil {
			log.Error("tunnel listener", "err", err)
		}
	}()

	g, err := relay.NewGateway(pool, log)
	if err != nil {
		return err
	}
	defer g.Close()
	as := g.AgentServer(credentials.NewTLS(agentTLS))
	lis, err := net.Listen("tcp", env("OPENRMM_LISTEN", ":8443"))
	if err != nil {
		return err
	}
	log.Info("gateway listening", "agents", lis.Addr().String(), "tunnel", rawTunnel.Addr().String())
	errCh := make(chan error, 1)
	go func() { errCh <- as.Serve(lis) }()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}
	stopped := make(chan struct{})
	go func() { as.GracefulStop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(15 * time.Second):
		as.Stop()
	}
	if err := <-errCh; err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}
