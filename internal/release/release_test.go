package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/stefanozanarini/open-rmm/internal/signing"
)

func TestSignVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, _ := signing.NewSigner(priv)
	keys := signing.NewKeyring()
	keys.Add(pub, signing.DomainAgentRelease)
	m := &Manifest{Version: "1.2.3", Platform: "windows/amd64", Files: []File{
		HashFile("openrmm-agent.exe", []byte("a")), HashFile("openrmm-watchdog.exe", []byte("w"))}}
	raw, sig, err := Sign(s, m)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Verify(keys, s.KeyID(), raw, sig)
	if err != nil || got.Version != "1.2.3" {
		t.Fatalf("verify: %v", err)
	}
	f, _ := got.File("openrmm-agent.exe")
	if f.CheckFile([]byte("a")) != nil || f.CheckFile([]byte("b")) == nil {
		t.Fatal("file check")
	}
	// A module key must not validate releases.
	other := signing.NewKeyring()
	other.Add(pub, signing.DomainModuleManifest)
	if _, err := Verify(other, s.KeyID(), raw, sig); err == nil {
		t.Fatal("release accepted with a key not trusted for releases")
	}
	// Linux file names on a Windows release are refused.
	bad := &Manifest{Version: "1.2.3", Platform: "windows/amd64", Files: []File{
		HashFile("openrmm-agent", []byte("a")), HashFile("openrmm-watchdog", []byte("w"))}}
	if _, _, err := Sign(s, bad); err == nil {
		t.Fatal("wrong file names accepted")
	}
}

func TestVersions(t *testing.T) {
	if !ParseRunning("0.0.0-dev").Less(Version{0, 0, 1}) || !ParseRunning("abc-dirty").Less(Version{0, 1, 0}) {
		t.Fatal("dev builds must be older than any release")
	}
	a, _ := ParseVersion("1.9.0")
	b, _ := ParseVersion("1.10.0")
	if !a.Less(b) || b.Less(a) || a.Less(a) {
		t.Fatal("ordering")
	}
	for _, s := range []string{"1.2", "v1.2.3", "01.2.3", "1.2.3-rc1"} {
		if _, err := ParseVersion(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}
