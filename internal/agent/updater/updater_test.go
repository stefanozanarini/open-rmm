package updater

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/open-rmm/internal/agent/config"
	"github.com/stefanozanarini/open-rmm/internal/pki"
	"github.com/stefanozanarini/open-rmm/internal/release"
	"github.com/stefanozanarini/open-rmm/internal/signing"
)

type fakeSession struct {
	files    map[string][]byte
	statuses []*openrmmv1.UpdateStatus
}

func (f *fakeSession) FetchRelease(context.Context, string, string) (map[string][]byte, error) {
	return f.files, nil
}
func (f *fakeSession) SendUpdateStatus(s *openrmmv1.UpdateStatus) { f.statuses = append(f.statuses, s) }

func setup(t *testing.T, running string) (*Updater, *signing.Signer, *config.Config) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, _ := signing.NewSigner(priv)
	dir := t.TempDir()
	root, _ := pki.NewRootCA("r", time.Now())
	os.WriteFile(filepath.Join(dir, "root.crt"), pki.EncodeCertPEM(root.Cert), 0o600)
	cfgFile := filepath.Join(dir, "agent.json")
	os.WriteFile(cfgFile, []byte(`{"server":"x:443","root_ca_file":"root.crt","data_dir":"`+filepath.Join(dir, "data")+
		`","install_dir":"`+filepath.Join(dir, "install")+`","release_signing_keys":["`+signing.EncodePublicKey(pub)+`"]}`), 0o600)
	cfg, err := config.Load(cfgFile)
	if err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(cfg.DataDir, 0o700)
	return New(cfg, running, slog.New(slog.NewTextHandler(io.Discard, nil))), s, cfg
}

func offer(t *testing.T, s *signing.Signer, version string) (*openrmmv1.SignedEnvelope, map[string][]byte) {
	files := map[string][]byte{release.AgentFile(runtime.GOOS): []byte("a" + version), release.WatchdogFile(runtime.GOOS): []byte("w" + version)}
	m := &release.Manifest{Version: version, Platform: runtime.GOOS + "/" + runtime.GOARCH}
	for n, d := range files {
		m.Files = append(m.Files, release.HashFile(n, d))
	}
	raw, sig, err := release.Sign(s, m)
	if err != nil {
		t.Fatal(err)
	}
	return &openrmmv1.SignedEnvelope{KeyId: s.KeyID(), Payload: raw, Signature: sig}, files
}

// Even if a (compromised) console offers an older signed release, the agent
// does not install it.
func TestRefusesDowngrade(t *testing.T) {
	u, s, cfg := setup(t, "2.0.0")
	env, files := offer(t, s, "1.9.9")
	sess := &fakeSession{files: files}
	if st := u.install(context.Background(), sess, env); st != nil {
		t.Fatalf("status %v", st)
	}
	if _, err := ReadPending(cfg.DataDir); err == nil {
		t.Fatal("downgrade staged")
	}
	env, files = offer(t, s, "2.0.0") // same version
	if st := u.install(context.Background(), &fakeSession{files: files}, env); st != nil {
		t.Fatalf("same version: %v", st)
	}
}

func TestSkipsRolledBackVersion(t *testing.T) {
	u, s, cfg := setup(t, "1.0.0")
	MarkFailed(cfg.DataDir, "1.1.0", "did not connect")
	env, files := offer(t, s, "1.1.0")
	if st := u.install(context.Background(), &fakeSession{files: files}, env); st != nil {
		t.Fatalf("rolled-back version retried: %v", st)
	}
	env, files = offer(t, s, "1.1.1")
	if st := u.install(context.Background(), &fakeSession{files: files}, env); st.GetState() != openrmmv1.UpdateStatus_STATE_STAGED {
		t.Fatalf("newer version: %v", st)
	}
}
