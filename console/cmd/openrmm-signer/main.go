// Command openrmm-signer holds the job signing key and signs jobs approved by
// an operator through a fresh multi-factor authentication. It listens on a
// Unix socket shared only with the console server, and needs outbound HTTPS
// to the identity provider (to fetch its signing keys), nothing else.
//
// Configuration (environment):
//
//	OPENRMM_SIGNER_KEY       job signing private key file
//	OPENRMM_SIGNER_SOCKET    socket path (default /run/openrmm-signer/signer.sock)
//	OPENRMM_SIGNER_STATE     used-token register (default /var/lib/openrmm-signer/used-tokens.json)
//	OPENRMM_OIDC_ISSUER, OPENRMM_OIDC_CLIENT_ID, OPENRMM_MFA_CLAIM, OPENRMM_TENANT_MAP
//	                         as for the console (see internal/console/authn)
package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"google.golang.org/grpc"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/open-rmm/internal/console/authn"
	"github.com/stefanozanarini/open-rmm/internal/console/signer"
	"github.com/stefanozanarini/open-rmm/internal/signing"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		c, err := net.DialTimeout("unix", env("OPENRMM_SIGNER_SOCKET", "/run/openrmm-signer/signer.sock"), 3*time.Second)
		if err != nil {
			os.Exit(1)
		}
		_ = c.Close()
		os.Exit(0)
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

func run(log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	keyPath := os.Getenv("OPENRMM_SIGNER_KEY")
	if keyPath == "" {
		return errors.New("OPENRMM_SIGNER_KEY is required")
	}
	raw, err := os.ReadFile(keyPath) // #nosec G304,G703 -- path set by the operator in the container configuration
	if err != nil {
		return err
	}
	key, err := signing.ParsePrivateKey(string(raw))
	if err != nil {
		return err
	}
	sg, err := signing.NewSigner(key)
	if err != nil {
		return err
	}
	cfg, err := authn.FromEnv()
	if err != nil {
		return err
	}
	// Discovery may fail while the network comes up: retry for a while.
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
	srv, err := signer.New(sg, v, env("OPENRMM_SIGNER_STATE", "/var/lib/openrmm-signer/used-tokens.json"), log)
	if err != nil {
		return err
	}

	sock := env("OPENRMM_SIGNER_SOCKET", "/run/openrmm-signer/signer.sock")
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
	gs := grpc.NewServer(grpc.MaxRecvMsgSize(2 << 20))
	openrmmv1.RegisterSignerServiceServer(gs, srv)
	log.Info("signer listening", "socket", sock, "key_id", sg.KeyID(), "issuer", cfg.Issuer, "mfa_claim", cfg.MFAClaim)
	go func() { <-ctx.Done(); gs.GracefulStop() }()
	return gs.Serve(lis)
}
