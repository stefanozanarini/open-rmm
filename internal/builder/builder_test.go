package builder

import (
	"bytes"
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/open-rmm/internal/codesign"
	"github.com/stefanozanarini/open-rmm/internal/pki"
)

const pass = "una passphrase lunga e sicura"

func newService(t *testing.T) *Service {
	_, file, _, _ := runtime.Caller(0)
	return &Service{Dir: t.TempDir(), WXS: filepath.Join(filepath.Dir(file), "..", "..", "packaging", "wix", "openrmm-agent.wxs"),
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

var subject = &openrmmv1.CertSubject{Organization: "Cliente Srl", OrganizationalUnit: "IT", Locality: "Bologna", Province: "BO", Country: "IT"}

func TestDedicatedCA(t *testing.T) {
	s := newService(t)
	ctx := context.Background()
	if st, _ := s.Status(ctx, nil); st.GetState() != "none" {
		t.Fatalf("state = %s", st.GetState())
	}
	if _, err := s.CreateCA(ctx, &openrmmv1.CreateCARequest{Subject: subject, Passphrase: "short"}); err == nil {
		t.Fatal("short passphrase accepted")
	}
	st, err := s.CreateCA(ctx, &openrmmv1.CreateCARequest{Subject: subject, Passphrase: pass})
	if err != nil {
		t.Fatal(err)
	}
	ch, err := codesign.ParseChain([]byte(st.GetChainPem()), time.Now())
	if err != nil || st.GetState() != "ready" || !st.GetDedicatedCa() || ch.Root() == nil || ch.Leaf.Subject.Locality[0] != "Bologna" {
		t.Fatalf("status = %+v, %v", st, err)
	}
	for _, f := range []string{fileKey, fileCAKey} {
		raw, _ := os.ReadFile(s.path(f))
		if !bytes.Contains(raw, []byte("ENCRYPTED PRIVATE KEY")) {
			t.Fatalf("%s not encrypted", f)
		}
		if fi, _ := os.Stat(s.path(f)); fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %v", f, fi.Mode())
		}
	}
	if _, err := s.Renew(ctx, &openrmmv1.RenewRequest{Passphrase: "wrong passphrase of length"}); err == nil {
		t.Fatal("renewed with a wrong passphrase")
	}
	st2, err := s.Renew(ctx, &openrmmv1.RenewRequest{Passphrase: pass})
	if err != nil || st2.GetChainPem() == st.GetChainPem() {
		t.Fatalf("renew: %v", err)
	}
}

func TestRequestAndImport(t *testing.T) {
	s := newService(t)
	ctx := context.Background()
	st, err := s.CreateRequest(ctx, &openrmmv1.CreateRequestRequest{Subject: subject, Passphrase: pass})
	if err != nil || st.GetState() != "pending" || !strings.Contains(st.GetRequestPem(), "CERTIFICATE REQUEST") {
		t.Fatalf("request: %+v %v", st, err)
	}
	// The enterprise CA signs the request.
	ca, _ := codesign.NewCA(codesign.Subject{Organization: "Corp Enterprise"}, time.Now())
	b, _ := pem.Decode([]byte(st.GetRequestPem()))
	csr, _ := x509.ParseCertificateRequest(b.Bytes)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "Cliente Srl"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}
	der, _ := x509.CreateCertificate(nil, tmpl, ca.Cert, csr.PublicKey, ca.Key)
	leaf, _ := x509.ParseCertificate(der)
	// A certificate for another key is refused.
	other, _ := ca.Issue(codesign.Subject{Organization: "X"}, time.Now())
	if _, err := s.ImportCertificate(ctx, &openrmmv1.ImportCertificateRequest{ChainPem: string(pki.EncodeCertPEM(other.Cert, ca.Cert))}); err == nil {
		t.Fatal("certificate of another key accepted")
	}
	st, err = s.ImportCertificate(ctx, &openrmmv1.ImportCertificateRequest{ChainPem: string(pki.EncodeCertPEM(leaf, ca.Cert))})
	if err != nil || st.GetState() != "ready" || st.GetRequestPem() != "" || st.GetDedicatedCa() {
		t.Fatalf("import: %+v %v", st, err)
	}
}

func TestImportPFX(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not installed")
	}
	dir := t.TempDir()
	ca, _ := codesign.NewCA(codesign.Subject{Organization: "Public CA"}, time.Now())
	leaf, _ := ca.Issue(codesign.Subject{Organization: "Cliente Srl"}, time.Now())
	keyPEM, _ := pki.EncodeKeyPEM(leaf.Key)
	os.WriteFile(filepath.Join(dir, "k.pem"), keyPEM, 0o600)
	os.WriteFile(filepath.Join(dir, "c.pem"), pki.EncodeCertPEM(leaf.Cert), 0o600)
	os.WriteFile(filepath.Join(dir, "ca.pem"), pki.EncodeCertPEM(ca.Cert), 0o600)
	pfx := filepath.Join(dir, "x.pfx")
	if out, err := exec.Command(openssl, "pkcs12", "-export", "-inkey", filepath.Join(dir, "k.pem"), "-in", filepath.Join(dir, "c.pem"),
		"-certfile", filepath.Join(dir, "ca.pem"), "-passout", "pass:pfxpass", "-out", pfx).CombinedOutput(); err != nil {
		t.Fatalf("openssl: %v %s", err, out)
	}
	raw, _ := os.ReadFile(pfx)
	s := newService(t)
	if _, err := s.ImportPFX(context.Background(), &openrmmv1.ImportPFXRequest{Pfx: raw, PfxPassword: "wrong", Passphrase: pass}); err == nil {
		t.Fatal("wrong PFX password accepted")
	}
	st, err := s.ImportPFX(context.Background(), &openrmmv1.ImportPFXRequest{Pfx: raw, PfxPassword: "pfxpass", Passphrase: pass})
	if err != nil || st.GetState() != "ready" {
		t.Fatalf("import PFX: %+v %v", st, err)
	}
	ch, _ := codesign.ParseChain([]byte(st.GetChainPem()), time.Now())
	if !codesign.MatchesKey(ch.Leaf, leaf.Key) || len(ch.CAs) != 1 {
		t.Fatal("chain not ordered leaf first")
	}
}

// buildStream collects the chunks of Build.
type buildStream struct {
	grpc.ServerStream
	buf bytes.Buffer
	sum string
}

func (b *buildStream) Context() context.Context    { return context.Background() }
func (b *buildStream) SetHeader(metadata.MD) error { return nil }
func (b *buildStream) Send(c *openrmmv1.BuildChunk) error {
	b.buf.Write(c.GetData())
	if c.GetSha256() != "" {
		b.sum = c.GetSha256()
	}
	return nil
}

func TestBuildSignedInstaller(t *testing.T) {
	for _, tool := range []string{"wixl", "msibuild", "msiinfo", "osslsigncode"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " not installed")
		}
	}
	s := newService(t)
	if _, err := s.CreateCA(context.Background(), &openrmmv1.CreateCARequest{Subject: subject, Passphrase: pass}); err != nil {
		t.Fatal(err)
	}
	// Any PE file will do: osslsigncode signs it, wixl packs it.
	exe := os.Getenv("OPENRMM_TEST_EXE")
	if exe == "" {
		t.Skip("set OPENRMM_TEST_EXE to a Windows executable")
	}
	pe, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	props := map[string]string{"SERVER": "agent.cliente.it:443", "ENROLLTOKEN": strings.Repeat("a", 43),
		"ROOTCA": strings.Repeat("QUJD", 40), "JOBSIGNINGKEYS": "ed25519:abc", "MODULESIGNINGKEYS": "ed25519:def", "RELEASESIGNINGKEYS": "ed25519:ghi"}
	req := &openrmmv1.BuildRequest{Version: "1.2.3", AgentExe: pe, WatchdogExe: pe, Properties: props, Passphrase: pass}
	if err := s.Build(&openrmmv1.BuildRequest{Version: "1.2.3", AgentExe: pe, WatchdogExe: pe, Passphrase: "wrong passphrase of length"}, &buildStream{}); err == nil {
		t.Fatal("built with a wrong passphrase")
	}
	if err := s.Build(&openrmmv1.BuildRequest{Version: "1.2.3", AgentExe: pe, WatchdogExe: pe, Passphrase: pass,
		Properties: map[string]string{"SERVER": "x'; DROP TABLE Property; --"}}, &buildStream{}); err == nil {
		t.Fatal("unsafe property accepted")
	}
	out := &buildStream{}
	if err := s.Build(req, out); err != nil {
		t.Fatal(err)
	}
	msi := filepath.Join(t.TempDir(), "a.msi")
	os.WriteFile(msi, out.buf.Bytes(), 0o600)
	if len(out.sum) != 64 {
		t.Fatal("no checksum")
	}
	ca, _ := os.ReadFile(s.path(fileCACert))
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(caFile, ca, 0o600)
	if v, err := exec.Command("osslsigncode", "verify", "-CAfile", caFile, "-in", msi).CombinedOutput(); err != nil {
		t.Fatalf("MSI signature: %v %s", err, v)
	}
	p, _ := exec.Command("msiinfo", "export", msi, "Property").CombinedOutput()
	for k, v := range props {
		if !strings.Contains(string(p), k+"\t"+v) {
			t.Errorf("property %s missing: %s", k, p)
		}
	}
	if !strings.Contains(string(p), "SecureCustomProperties\t") || !strings.Contains(string(p), "ENROLLTOKEN") {
		t.Errorf("secure properties: %s", p)
	}
}

// TestRunningBuilder drives a running openrmm-builder (e.g. the container)
// through its socket: OPENRMM_TEST_BUILDER_SOCKET and OPENRMM_TEST_EXE.
func TestRunningBuilder(t *testing.T) {
	sock, exe := os.Getenv("OPENRMM_TEST_BUILDER_SOCKET"), os.Getenv("OPENRMM_TEST_EXE")
	if sock == "" || exe == "" {
		t.Skip("set OPENRMM_TEST_BUILDER_SOCKET and OPENRMM_TEST_EXE")
	}
	conn, err := grpc.NewClient("unix://"+sock, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	c := openrmmv1.NewBuilderServiceClient(conn)
	ctx := context.Background()
	if _, err := c.CreateCA(ctx, &openrmmv1.CreateCARequest{Subject: subject, Passphrase: pass}); err != nil {
		t.Fatal(err)
	}
	pe, _ := os.ReadFile(exe)
	stream, err := c.Build(ctx, &openrmmv1.BuildRequest{Version: "1.2.3", AgentExe: pe, WatchdogExe: pe, Passphrase: pass,
		Properties: map[string]string{"SERVER": "agent.cliente.it:443"}}, grpc.MaxCallSendMsgSize(256<<20))
	if err != nil {
		t.Fatal(err)
	}
	var size int
	var sum string
	for {
		ch, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		size += len(ch.GetData())
		if ch.GetSha256() != "" {
			sum = ch.GetSha256()
		}
	}
	if size < 100000 || len(sum) != 64 {
		t.Fatalf("installer of %d bytes, sum %q", size, sum)
	}
	t.Logf("installer: %d bytes, sha256 %s", size, sum)
}
