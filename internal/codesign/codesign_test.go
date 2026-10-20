package codesign

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/pki"
)

func TestDedicatedCAChain(t *testing.T) {
	now := time.Now()
	s := Subject{Organization: "Cliente Srl", Country: "it"}
	ca, err := NewCA(s, now)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.Issue(s, now)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Cert.Subject.CommonName != "Cliente Srl" || ca.Cert.Subject.CommonName != "Cliente Srl Code Signing CA" ||
		leaf.Cert.Subject.Country[0] != "IT" {
		t.Fatalf("subjects: %s / %s", leaf.Cert.Subject, ca.Cert.Subject)
	}
	if !MatchesKey(leaf.Cert, leaf.Key) || MatchesKey(leaf.Cert, ca.Key) {
		t.Fatal("MatchesKey")
	}
	ch, err := ParseChain(pki.EncodeCertPEM(leaf.Cert, ca.Cert), now)
	if err != nil {
		t.Fatal(err)
	}
	if ch.Root() == nil || ch.Root().Subject.CommonName != ca.Cert.Subject.CommonName || ch.Expiring(now) {
		t.Fatalf("chain = %+v", ch)
	}
	if !ch.Expiring(now.Add(SigningValidity - 30*24*time.Hour)) {
		t.Fatal("expiry warning")
	}
	if i := ch.LeafInfo(); len(i.Thumbprint) != 40 || i.SelfSigned {
		t.Fatalf("info = %+v", i)
	}
	// The CA itself cannot sign code.
	if _, err := ParseChain(pki.EncodeCertPEM(ca.Cert), now); err == nil || !strings.Contains(err.Error(), "CA certificate") {
		t.Fatalf("CA accepted as signing certificate: %v", err)
	}
	// A chain to another CA is refused.
	other, _ := NewCA(s, now)
	if _, err := ParseChain(pki.EncodeCertPEM(leaf.Cert, other.Cert), now); err == nil {
		t.Fatal("wrong CA accepted")
	}
	// Keys are never accepted.
	key, _ := pki.EncodeKeyPEM(leaf.Key)
	if _, err := ParseChain(append(pki.EncodeCertPEM(leaf.Cert), key...), now); err == nil || !strings.Contains(err.Error(), "never a key") {
		t.Fatalf("key accepted: %v", err)
	}
	if _, err := ParseChain(pki.EncodeCertPEM(leaf.Cert), now.Add(4*SigningValidity)); err == nil {
		t.Fatal("expired certificate accepted")
	}
}

func TestRequest(t *testing.T) {
	key, csrPEM, err := NewRequest(Subject{Organization: "Cliente Srl", CommonName: "Cliente Srl IT"})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := pem.Decode(csrPEM)
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil || csr.CheckSignature() != nil || csr.Subject.CommonName != "Cliente Srl IT" {
		t.Fatalf("csr: %v", err)
	}
	if key == nil {
		t.Fatal("no key")
	}
	if _, _, err := NewRequest(Subject{}); err == nil {
		t.Fatal("empty organization accepted")
	}
}

func TestServerCertificateRefused(t *testing.T) {
	root, _ := pki.NewRootCA("r", time.Now())
	ca, _ := pki.NewIntermediateCA(root, "i", time.Now())
	srv, _, _ := ca.IssueServer([]string{"a.example"}, time.Now())
	if err := CheckSigning(srv, time.Now()); err == nil || !strings.Contains(err.Error(), "code signing") {
		t.Fatalf("server certificate accepted: %v", err)
	}
}

func TestEncryptedKey(t *testing.T) {
	ca, _ := NewCA(Subject{Organization: "Cliente Srl", OrganizationalUnit: "IT", Locality: "Bologna", Province: "BO", Country: "IT"}, time.Now())
	if ca.Cert.Subject.Locality[0] != "Bologna" || ca.Cert.Subject.OrganizationalUnit[0] != "IT" {
		t.Fatalf("subject = %s", ca.Cert.Subject)
	}
	pass := "una frase lunga abbastanza"
	enc, err := EncryptKeyPEM(ca.Key, pass)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(enc), "BEGIN PRIVATE KEY") {
		t.Fatal("key in clear")
	}
	key, err := DecryptKeyPEM(enc, pass)
	if err != nil || !MatchesKey(ca.Cert, key) {
		t.Fatalf("decrypt: %v", err)
	}
	if _, err := DecryptKeyPEM(enc, pass+"x"); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
	if _, err := EncryptKeyPEM(ca.Key, "short"); err == nil {
		t.Fatal("short passphrase accepted")
	}
}

// OpenSSL (and so osslsigncode) must read the encrypted keys.
func TestEncryptedKeyOpenSSL(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not installed")
	}
	ca, _ := NewCA(Subject{Organization: "Cliente Srl"}, time.Now())
	pass := "una frase lunga abbastanza"
	enc, _ := EncryptKeyPEM(ca.Key, pass)
	f := filepath.Join(t.TempDir(), "k.pem")
	os.WriteFile(f, enc, 0o600)
	out, err := exec.Command(openssl, "pkey", "-in", f, "-passin", "pass:"+pass, "-pubout").CombinedOutput()
	if err != nil {
		t.Fatalf("openssl: %v %s", err, out)
	}
	want, _ := x509.MarshalPKIXPublicKey(ca.Cert.PublicKey)
	if b, _ := pem.Decode(out); b == nil || string(b.Bytes) != string(want) {
		t.Fatalf("openssl read another key: %s", out)
	}
}
