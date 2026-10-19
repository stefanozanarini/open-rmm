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
// Federation (docs/FEDERATION.md), central console:
//
//	OPENRMM_FEDERATION_LISTEN          listener for the links of customer consoles (e.g. :8445)
//	OPENRMM_FEDERATION_PUBLIC_ADDR     host:port customer consoles dial (put in link tokens)
//
// Customer console: OPENRMM_FEDERATION_* of authn.FederationFromEnv (the
// central console's directory, also configured on the signer).
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
	"github.com/stefanozanarini/open-rmm/internal/console/pkgfiles"
	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/console/web"
	"github.com/stefanozanarini/open-rmm/internal/federation"
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
	fed, err := setupFederation(ctx, log, db)
	if err != nil {
		return err
	}
	conn, err := grpc.NewClient("unix://"+env("OPENRMM_SIGNER_SOCKET", "/run/openrmm-signer/signer.sock"),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	defer conn.Close()
	srv, err := web.New(web.Config{
		Store: db, Verifier: v, Signer: openrmmv1.NewSignerServiceClient(conn), Logger: log,
		PublicURL: publicURL, ClientSecret: strings.TrimSpace(string(secret)),
		Packages: pkgfiles.Dir{Path: env("OPENRMM_PACKAGES_DIR", "/var/lib/openrmm/packages")},
		Hub:      fed.hub, LinkAddr: fed.linkAddr, FedVerifier: fed.verifier, Uplink: fed.uplink,
	})
	if err != nil {
		return err
	}
	if err := fed.start(ctx, log, srv); err != nil {
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

type fedSetup struct {
	hub      *federation.Hub
	listen   string
	linkAddr string
	verifier *authn.Verifier
	uplink   *federation.Uplink
}

// setupFederation reads the federation settings: the central side when a
// link listener is configured, the customer side when a central directory
// is trusted. A console may have neither.
func setupFederation(ctx context.Context, log *slog.Logger, db *store.Postgres) (*fedSetup, error) {
	f := &fedSetup{listen: os.Getenv("OPENRMM_FEDERATION_LISTEN"), linkAddr: os.Getenv("OPENRMM_FEDERATION_PUBLIC_ADDR")}
	if f.listen != "" {
		if f.linkAddr == "" {
			return nil, errors.New("OPENRMM_FEDERATION_PUBLIC_ADDR is required with OPENRMM_FEDERATION_LISTEN")
		}
		id, err := federation.CentralIdentity(ctx, db, time.Now())
		if err != nil {
			return nil, err
		}
		f.hub = &federation.Hub{Store: db, ID: id, Log: log}
	}
	cfg, ok, err := authn.FederationFromEnv()
	if err != nil {
		return nil, err
	}
	if ok {
		for attempt := 0; ; attempt++ {
			if f.verifier, err = authn.NewVerifier(ctx, cfg); err == nil {
				break
			}
			if attempt >= 30 || ctx.Err() != nil {
				return nil, err
			}
			log.Warn("central console directory not reachable yet", "err", err)
			time.Sleep(5 * time.Second)
		}
		f.uplink = &federation.Uplink{Store: db, Log: log}
	}
	return f, nil
}

func (f *fedSetup) start(ctx context.Context, log *slog.Logger, srv *web.Server) error {
	if f.hub != nil {
		lis, err := net.Listen("tcp", f.listen)
		if err != nil {
			return err
		}
		log.Info("federation link listener", "addr", f.listen, "public", f.linkAddr, "fingerprint", f.hub.ID.Fingerprint)
		go func() {
			if err := f.hub.Serve(ctx, lis); err != nil {
				log.Error("federation listener stopped", "err", err)
			}
		}()
		go f.hub.RunSummaries(ctx)
	}
	if f.uplink != nil {
		f.uplink.Handler = srv.LinkHandler()
		go f.uplink.Run(ctx)
	}
	return nil
}
