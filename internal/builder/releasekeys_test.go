package builder

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/open-rmm/internal/modules"
	"github.com/stefanozanarini/open-rmm/internal/release"
	"github.com/stefanozanarini/open-rmm/internal/signing"
)

func moduleManifest(t *testing.T) []byte {
	t.Helper()
	zero := string(bytes.Repeat([]byte("0"), 64))
	m := &modules.Manifest{ProtocolVersion: modules.ProtocolVersion, ID: "inventory", Version: "1.0.0", Description: "test",
		Entrypoints:   map[string]modules.Entrypoint{"windows/amd64": {Type: modules.TypePowerShell, Path: "Main.ps1"}},
		Actions:       map[string]modules.Action{"collect": {TimeoutSeconds: 60}},
		Files:         []modules.File{{Path: "Main.ps1", SHA256: zero, Size: 1}},
		ArchiveSHA256: zero,
	}
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := modules.ParseManifest(raw); err != nil {
		t.Fatalf("test manifest invalid: %v", err)
	}
	return raw
}

func releaseManifest(t *testing.T) []byte {
	t.Helper()
	m := &release.Manifest{Version: "1.2.3", Platform: "windows/amd64", ReleasedAt: time.Now().UTC(),
		Files: []release.File{release.HashFile("openrmm-agent.exe", []byte("a")), release.HashFile("openrmm-watchdog.exe", []byte("w"))}}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func code(err error) codes.Code { return status.Code(err) }

func TestReleaseKeys(t *testing.T) {
	s := newService(t)
	ctx := context.Background()
	// One passphrase for every key: the code-signing key comes first here.
	if _, err := s.CreateCA(ctx, &openrmmv1.CreateCARequest{Subject: subject, Passphrase: pass}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateReleaseKeys(ctx, &openrmmv1.CreateReleaseKeysRequest{Passphrase: "another long passphrase"}); code(err) != codes.PermissionDenied {
		t.Fatalf("different passphrase: %v", err)
	}
	st, err := s.CreateReleaseKeys(ctx, &openrmmv1.CreateReleaseKeysRequest{Passphrase: pass})
	if err != nil {
		t.Fatal(err)
	}
	modPub, err := signing.ParsePublicKey(st.GetModuleKey())
	if err != nil {
		t.Fatal(err)
	}
	relPub, err := signing.ParsePublicKey(st.GetReleaseKey())
	if err != nil || modPub.Equal(relPub) {
		t.Fatalf("release key %q: %v", st.GetReleaseKey(), err)
	}
	for _, f := range []string{fileModuleKey, fileReleaseKey} {
		raw, _ := os.ReadFile(s.path(f))
		if !bytes.Contains(raw, []byte("ENCRYPTED PRIVATE KEY")) {
			t.Fatalf("%s not encrypted", f)
		}
	}
	if _, err := s.CreateReleaseKeys(ctx, &openrmmv1.CreateReleaseKeysRequest{Passphrase: pass}); code(err) != codes.AlreadyExists {
		t.Fatalf("keys replaced: %v", err)
	}
	// Replacing the code-signing material keeps the same passphrase.
	if _, err := s.CreateCA(ctx, &openrmmv1.CreateCARequest{Subject: subject, Passphrase: "another long passphrase"}); code(err) != codes.PermissionDenied {
		t.Fatalf("CA with another passphrase: %v", err)
	}

	keys := signing.NewKeyring()
	if _, err := keys.Add(modPub, signing.DomainModuleManifest); err != nil {
		t.Fatal(err)
	}
	if _, err := keys.Add(relPub, signing.DomainAgentRelease); err != nil {
		t.Fatal(err)
	}
	mod := moduleManifest(t)
	res, err := s.SignManifest(ctx, &openrmmv1.SignManifestRequest{Kind: KindModule, Manifest: mod, Passphrase: pass})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := modules.VerifyManifest(keys, res.GetKeyId(), mod, res.GetSignature()); err != nil {
		t.Fatalf("module signature: %v", err)
	}
	rel := releaseManifest(t)
	res, err = s.SignManifest(ctx, &openrmmv1.SignManifestRequest{Kind: KindRelease, Manifest: rel, Passphrase: pass})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := release.Verify(keys, res.GetKeyId(), rel, res.GetSignature()); err != nil {
		t.Fatalf("release signature: %v", err)
	}

	for name, req := range map[string]*openrmmv1.SignManifestRequest{
		"wrong passphrase":  {Kind: KindModule, Manifest: mod, Passphrase: "wrong passphrase, long"},
		"release as module": {Kind: KindModule, Manifest: rel, Passphrase: pass},
		"module as release": {Kind: KindRelease, Manifest: mod, Passphrase: pass},
		"arbitrary bytes":   {Kind: KindModule, Manifest: []byte(`{"anything":1}`), Passphrase: pass},
		"unknown kind":      {Kind: "job", Manifest: mod, Passphrase: pass},
	} {
		if _, err := s.SignManifest(ctx, req); err == nil {
			t.Errorf("%s: signed", name)
		}
	}
}

func TestSignWithoutKeys(t *testing.T) {
	s := newService(t)
	_, err := s.SignManifest(context.Background(), &openrmmv1.SignManifestRequest{Kind: KindModule, Manifest: moduleManifest(t), Passphrase: pass})
	if code(err) != codes.FailedPrecondition {
		t.Fatalf("err = %v", err)
	}
}
