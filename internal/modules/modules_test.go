package modules

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stefanozanarini/open-rmm/internal/signing"
)

func baseManifest() *Manifest {
	return &Manifest{
		ID: "demo", Version: "1.2.3", ProtocolVersion: ProtocolVersion,
		Entrypoints: map[string]Entrypoint{"linux/amd64": {Type: TypeShell, Path: "main.sh"}},
		Actions:     map[string]Action{"run": {TimeoutSeconds: 60}},
	}
}

func srcDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for p, c := range files {
		full := filepath.Join(dir, filepath.FromSlash(p))
		os.MkdirAll(filepath.Dir(full), 0o700)
		if err := os.WriteFile(full, []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestPackSignVerifyExtract(t *testing.T) {
	m := baseManifest()
	archive, err := Pack(m, srcDir(t, map[string]string{"main.sh": "echo hi", "lib/util.sh": "x=1"}),
		map[string][]byte{"_sdk/openrmm.sh": []byte("sdk")})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Files) != 3 {
		t.Fatalf("files = %+v", m.Files)
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, _ := signing.NewSigner(priv)
	b, err := SignBundle(s, m, archive)
	if err != nil {
		t.Fatal(err)
	}
	keys := signing.NewKeyring()
	keys.Add(pub, signing.DomainModuleManifest)
	v, err := b.Verify(keys)
	if err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "x")
	if err := Extract(v.Manifest, b.Archive, dest); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(dest, "lib", "util.sh")); string(got) != "x=1" {
		t.Fatalf("extracted content = %q", got)
	}
	if err := VerifyFiles(v.Manifest, dest); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dest, "main.sh"), []byte("echo pwned"), 0o600)
	if err := VerifyFiles(v.Manifest, dest); err == nil {
		t.Fatal("modified file not detected")
	}

	// A job signing key must not validate manifests.
	jobKeys := signing.NewKeyring()
	jobKeys.Add(pub, signing.DomainJob)
	if _, err := b.Verify(jobKeys); err == nil {
		t.Fatal("manifest accepted with a key not trusted for modules")
	}
	// Tampering with the archive breaks the pinned hash.
	b.Archive = append([]byte(nil), b.Archive...)
	b.Archive[len(b.Archive)/2] ^= 0xff
	if _, err := b.Verify(keys); err == nil {
		t.Fatal("tampered archive accepted")
	}
}

func TestManifestValidation(t *testing.T) {
	cases := map[string]func(*Manifest){
		"bad id":       func(m *Manifest) { m.ID = "Demo" },
		"bad version":  func(m *Manifest) { m.Version = "1.2" },
		"bad platform": func(m *Manifest) { m.Entrypoints = map[string]Entrypoint{"darwin/amd64": {Type: TypeShell, Path: "a"}} },
		"bad type":     func(m *Manifest) { m.Entrypoints = map[string]Entrypoint{"linux/amd64": {Type: "python", Path: "a"}} },
		"traversal": func(m *Manifest) {
			m.Entrypoints = map[string]Entrypoint{"linux/amd64": {Type: TypeShell, Path: "../a"}}
		},
		"absolute": func(m *Manifest) {
			m.Entrypoints = map[string]Entrypoint{"linux/amd64": {Type: TypeShell, Path: "/bin/sh"}}
		},
		"backslash": func(m *Manifest) {
			m.Entrypoints = map[string]Entrypoint{"linux/amd64": {Type: TypeShell, Path: `a\b`}}
		},
		"drive": func(m *Manifest) {
			m.Entrypoints = map[string]Entrypoint{"windows/amd64": {Type: TypeBinary, Path: "C:x.exe"}}
		},
		"timeout too long": func(m *Manifest) { m.Actions = map[string]Action{"run": {TimeoutSeconds: 5 * 3600}} },
		"bad context":      func(m *Manifest) { m.Actions = map[string]Action{"run": {Context: "root"}} },
		"bad capability":   func(m *Manifest) { m.Capabilities = []string{"kernel"} },
		"no actions":       func(m *Manifest) { m.Actions = nil },
	}
	for name, mutate := range cases {
		m := baseManifest()
		mutate(m)
		if err := m.Validate(false); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestPackRejectsCaseInsensitiveDuplicates(t *testing.T) {
	m := baseManifest()
	if _, err := Pack(m, srcDir(t, map[string]string{"main.sh": "a", "Main.sh": "b"}), nil); err == nil {
		t.Fatal("files differing only by case accepted")
	}
}

func TestPackRequiresEntrypoint(t *testing.T) {
	if _, err := Pack(baseManifest(), srcDir(t, map[string]string{"other.sh": "a"}), nil); err == nil {
		t.Fatal("missing entrypoint accepted")
	}
}

// craft builds a zip by hand, bypassing Pack.
func craft(t *testing.T, members map[string]string) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range members {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(content))
	}
	zw.Close()
	return buf.Bytes()
}

func manifestFor(t *testing.T, archive []byte, files map[string]string) *Manifest {
	m := baseManifest()
	for p, c := range files {
		m.Files = append(m.Files, File{Path: p, SHA256: hexSHA256([]byte(c)), Size: int64(len(c))})
	}
	m.ArchiveSHA256 = hexSHA256(archive)
	return m
}

func TestExtractRejectsHostileArchives(t *testing.T) {
	// An extra member not listed in the manifest.
	a := craft(t, map[string]string{"main.sh": "ok", "../evil": "x"})
	m := manifestFor(t, a, map[string]string{"main.sh": "ok"})
	if err := Extract(m, a, filepath.Join(t.TempDir(), "x")); err == nil {
		t.Error("unlisted member accepted")
	}
	// Content larger than declared (zip bomb style).
	big := strings.Repeat("A", 1<<20)
	a = craft(t, map[string]string{"main.sh": big})
	m = manifestFor(t, a, map[string]string{"main.sh": "short"})
	if err := Extract(m, a, filepath.Join(t.TempDir(), "x")); err == nil {
		t.Error("oversized member accepted")
	}
	// Right size, wrong content.
	a = craft(t, map[string]string{"main.sh": "evil!"})
	m = manifestFor(t, a, map[string]string{"main.sh": "good!"})
	if err := Extract(m, a, filepath.Join(t.TempDir(), "x")); err == nil {
		t.Error("member with a different hash accepted")
	}
	// Archive not matching the manifest hash at all.
	m.ArchiveSHA256 = hexSHA256([]byte("other"))
	if err := Extract(m, a, filepath.Join(t.TempDir(), "x")); err == nil {
		t.Error("archive hash mismatch accepted")
	}
}
