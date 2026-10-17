// Command openrmm-server serves the operator web console. It is meant for
// the LAN or VPN of the operators, not for the internet.
//
// Configuration (environment):
//
//	OPENRMM_DATABASE_URL               PostgreSQL connection string
//	OPENRMM_PUBLIC_URL                 console URL as seen by browsers (https://...)
//	OPENRMM_HTTP_LISTEN                listen address (default :8080)
//	OPENRMM_TLS_CERT, OPENRMM_TLS_KEY  serve HTTPS with these files; without them
//	                                   the console serves plain HTTP and must sit
//	                                   behind a TLS reverse proxy
//	OPENRMM_OIDC_CLIENT_SECRET_FILE    file with the Entra application secret
//	OPENRMM_SIGNER_SOCKET              signer socket (default /run/openrmm-signer/signer.sock)
//	OPENRMM_OIDC_ISSUER, OPENRMM_OIDC_CLIENT_ID, OPENRMM_MFA_CLAIM, OPENRMM_TENANT_MAP
//	                                   see internal/console/authn
//
// "openrmm-server healthcheck" exits 0 if the console answers on /healthz.
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
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/open-rmm/internal/console/authn"
	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/console/web"
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
	_, port, err := net.SplitHostPort(env("OPENRMM_HTTP_LISTEN", ":8080"))
	if err != nil {
		return 1
	}
	scheme := "http"
	if os.Getenv("OPENRMM_TLS_CERT") != "" {
		scheme = "https"
	}
	c := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402 -- loopback health check only
	}}
	resp, err := c.Get(scheme + "://127.0.0.1:" + port + "/healthz")
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

	cfg, err := authn.FromEnv()
	if err != nil {
		return err
	}
	secretFile := os.Getenv("OPENRMM_OIDC_CLIENT_SECRET_FILE")
	if secretFile == "" {
		return errors.New("OPENRMM_OIDC_CLIENT_SECRET_FILE is required")
	}
	secret, err := os.ReadFile(secretFile) // #nosec G304,G703 -- path set by the operator in the container configuration
	if err != nil {
		return err
	}
	publicURL := os.Getenv("OPENRMM_PUBLIC_URL")
	if publicURL == "" {
		return errors.New("OPENRMM_PUBLIC_URL is required")
	}
	db, err := store.OpenPostgres(ctx, os.Getenv("OPENRMM_DATABASE_URL"))
	if err != nil {
		return err
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		return err
	}
	var v *authn.Verifier
	for attempt := 0; ; attempt++ {
		v, err = authn.NewVerifier(ctx, cfg)
		if err == nil {
			break
		}
		if attempt >= 30 || ctx.Err() != nil {
			return err
		}
		log.Warn("identity provider not reachable yet", "err", err)
		time.Sleep(5 * time.Second)
	}
	// The signer is reached over a local Unix socket shared between the two
	// containers; it authenticates requests by their id_token, not by the
	// channel.
	conn, err := grpc.NewClient("unix://"+env("OPENRMM_SIGNER_SOCKET", "/run/openrmm-signer/signer.sock"),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	defer conn.Close()
	srv, err := web.New(web.Config{
		Store: db, Verifier: v, Signer: openrmmv1.NewSignerServiceClient(conn), Logger: log,
		PublicURL: publicURL, ClientSecret: strings.TrimSpace(string(secret)),
	})
	if err != nil {
		return err
	}
	go func() {
		t := time.NewTicker(10 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := db.DeleteExpiredSessions(ctx, time.Now()); err != nil {
					log.Error("session cleanup", "err", err)
				}
			}
		}
	}()

	hs := &http.Server{
		Addr:              env("OPENRMM_HTTP_LISTEN", ":8080"),
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}
	errCh := make(chan error, 1)
	go func() {
		cert, key := os.Getenv("OPENRMM_TLS_CERT"), os.Getenv("OPENRMM_TLS_KEY")
		log.Info("console listening", "addr", hs.Addr, "public_url", publicURL, "tls", cert != "")
		if cert != "" {
			hs.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
			errCh <- hs.ListenAndServeTLS(cert, key)
			return
		}
		errCh <- hs.ListenAndServe()
	}()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := hs.Shutdown(sctx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	return nil
}
