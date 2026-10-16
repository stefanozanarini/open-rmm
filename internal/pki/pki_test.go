package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/ids"
)

func newHierarchy(t *testing.T) (*CA, *CA) {
	t.Helper()
	now := time.Now()
	root, err := NewRootCA("test root", now)
	if err != nil {
		t.Fatal(err)
	}
	inter, err := NewIntermediateCA(root, "test agents", now)
	if err != nil {
		t.Fatal(err)
	}
	return root, inter
}

func csr(t *testing.T, tmpl *x509.CertificateRequest, key any) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestIssueAgentChainsAndCarriesIdentity(t *testing.T) {
	root, inter := newHierarchy(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id := Identity{TenantID: ids.NewUUID(), AgentID: ids.NewUUID()}
	// The requester tries to smuggle its own SAN: it must be ignored.
	evil, _ := url.Parse("openrmm://tenants/" + ids.NewUUID() + "/agents/" + ids.NewUUID())
	cert, err := inter.IssueAgent(csr(t, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "pc01"}, URIs: []*url.URL{evil}, DNSNames: []string{"evil.example"},
	}, key), id, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.DNSNames) != 0 || len(cert.URIs) != 1 {
		t.Fatalf("CSR SANs leaked into certificate: %v %v", cert.DNSNames, cert.URIs)
	}
	got, err := IdentityFromCert(cert)
	if err != nil || got != id {
		t.Fatalf("identity = %+v, %v; want %+v", got, err, id)
	}
	roots, inters := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root.Cert)
	inters.AddCert(inter.Cert)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("verify: %v", err)
	}
	// An agent certificate must not be usable as a server certificate.
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err == nil {
		t.Fatal("agent certificate verified for server auth")
	}
	if cert.IsCA {
		t.Fatal("agent certificate is a CA")
	}
}

func TestIssueAgentRejectsBadCSR(t *testing.T) {
	_, inter := newHierarchy(t)
	id := Identity{TenantID: ids.NewUUID(), AgentID: ids.NewUUID()}
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	good, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tampered := csr(t, &x509.CertificateRequest{}, good)
	tampered[len(tampered)-1] ^= 0xff
	for name, der := range map[string][]byte{
		"rsa":      csr(t, &x509.CertificateRequest{}, rsaKey),
		"p384":     csr(t, &x509.CertificateRequest{}, p384),
		"tampered": tampered,
		"garbage":  []byte("not a csr"),
		"empty":    nil,
	} {
		if _, err := inter.IssueAgent(der, id, time.Now()); !errors.Is(err, ErrBadCSR) {
			t.Errorf("%s: err = %v, want ErrBadCSR", name, err)
		}
	}
}

func TestIntermediateCannotIssueCAs(t *testing.T) {
	_, inter := newHierarchy(t)
	if !inter.Cert.MaxPathLenZero || inter.Cert.MaxPathLen != 0 {
		t.Fatal("agents CA must have pathlen 0")
	}
}

func TestIdentityFromCertRejectsMalformed(t *testing.T) {
	for _, raw := range []string{
		"openrmm://tenants/not-a-uuid/agents/" + ids.NewUUID(),
		"openrmm://tenants/" + ids.NewUUID() + "/agents/" + ids.NewUUID() + "/extra",
	} {
		u, _ := url.Parse(raw)
		if _, err := IdentityFromCert(&x509.Certificate{URIs: []*url.URL{u}}); err == nil {
			t.Errorf("%s accepted", raw)
		}
	}
	u1, _ := url.Parse("openrmm://tenants/" + ids.NewUUID() + "/agents/" + ids.NewUUID())
	u2, _ := url.Parse("openrmm://tenants/" + ids.NewUUID() + "/agents/" + ids.NewUUID())
	if _, err := IdentityFromCert(&x509.Certificate{URIs: []*url.URL{u1, u2}}); err == nil {
		t.Error("two identities accepted")
	}
}

func TestLoadCARejectsMismatchedKey(t *testing.T) {
	root, inter := newHierarchy(t)
	key, _ := EncodeKeyPEM(inter.Key)
	if _, err := LoadCA(EncodeCertPEM(root.Cert), key); err == nil {
		t.Fatal("mismatched key accepted")
	}
	if _, err := LoadCA(EncodeCertPEM(inter.Cert), key); err != nil {
		t.Fatal(err)
	}
}
