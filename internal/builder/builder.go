// Package builder implements openrmm-builder: it holds the console's signing
// keys, encrypted with one passphrase that is never stored, builds signed
// agent installers (MSI) preconfigured for this console, and signs module and
// agent release manifests.
//
// The key is created here (dedicated CA, or a request for an enterprise
// CA) or imported from a PFX, and is never written in clear: OpenSSL and
// osslsigncode read the encrypted PKCS#8 file with the passphrase given for
// each operation, through a pipe.
package builder

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/open-rmm/internal/codesign"
	"github.com/stefanozanarini/open-rmm/internal/pki"
)

// State files, in Dir.
const (
	fileKey        = "signing.key" // encrypted
	fileChain      = "signing.crt" // signing certificate, then its CAs
	fileCAKey      = "ca.key"      // encrypted, dedicated CA only
	fileCACert     = "ca.crt"
	fileRequestKey = "request.key" // encrypted, pending request
	fileRequest    = "request.csr"

	chunkSize = 1 << 20
	// MaxExecutable bounds the executables of a build.
	MaxExecutable = 64 << 20
)

// Properties that a build may preset in the MSI.
var buildProperties = map[string]*regexp.Regexp{
	"SERVER":             regexp.MustCompile(`^[A-Za-z0-9.-]{1,253}:[0-9]{1,5}$`),
	"ROOTCA":             regexp.MustCompile(`^[A-Za-z0-9+/=]+$`),
	"ENROLLTOKEN":        regexp.MustCompile(`^[A-Za-z0-9_-]{20,200}$`),
	"JOBSIGNINGKEYS":     regexp.MustCompile(`^[A-Za-z0-9:+/=,;]+$`),
	"MODULESIGNINGKEYS":  regexp.MustCompile(`^[A-Za-z0-9:+/=,;]+$`),
	"RELEASESIGNINGKEYS": regexp.MustCompile(`^[A-Za-z0-9:+/=,;]+$`),
}

var (
	versionRe = regexp.MustCompile(`^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,6}$`)
	tsRe      = regexp.MustCompile(`^https?://[A-Za-z0-9./:_-]{1,200}$`)
)

// Service implements openrmmv1.BuilderServiceServer.
type Service struct {
	openrmmv1.UnimplementedBuilderServiceServer

	Dir string // state, owner only
	WXS string // MSI source (packaging/wix/openrmm-agent.wxs)
	Log *slog.Logger
	Now func() time.Time

	mu sync.Mutex
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) path(name string) string { return filepath.Join(s.Dir, name) }

func (s *Service) exists(name string) bool {
	_, err := os.Stat(s.path(name))
	return err == nil
}

// write replaces a state file atomically, readable by the owner only.
func (s *Service) write(name string, data []byte) error {
	tmp := s.path(name + ".tmp")
	if err := os.WriteFile(tmp, data, 0o600); err != nil { // #nosec G703 -- fixed file names in the state directory
		return err
	}
	return os.Rename(tmp, s.path(name))
}

// archive moves the current material aside before it is replaced.
func (s *Service) archive() error {
	dir := s.path(filepath.Join("archive", s.now().UTC().Format("20060102T150405")))
	moved := false
	for _, f := range []string{fileKey, fileChain, fileCAKey, fileCACert} {
		if !s.exists(f) {
			continue
		}
		if !moved {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return err
			}
			moved = true
		}
		if err := os.Rename(s.path(f), filepath.Join(dir, f)); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) status() (*openrmmv1.BuilderStatus, error) {
	st := &openrmmv1.BuilderStatus{State: "none", DedicatedCa: s.exists(fileCAKey),
		ModuleKey: s.publicKey(fileModuleKey), ReleaseKey: s.publicKey(fileReleaseKey)}
	if chain, err := os.ReadFile(s.path(fileChain)); err == nil && s.exists(fileKey) {
		st.State, st.ChainPem = "ready", string(chain)
	}
	if req, err := os.ReadFile(s.path(fileRequest)); err == nil {
		st.RequestPem = string(req)
		if st.State == "none" {
			st.State = "pending"
		}
	}
	return st, nil
}

// Status reports the signing material.
func (s *Service) Status(context.Context, *openrmmv1.BuilderStatusRequest) (*openrmmv1.BuilderStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status()
}

func subjectOf(p *openrmmv1.CertSubject) codesign.Subject {
	return codesign.Subject{Organization: p.GetOrganization(), CommonName: p.GetCommonName(), Country: p.GetCountry(),
		OrganizationalUnit: p.GetOrganizationalUnit(), Locality: p.GetLocality(), Province: p.GetProvince()}
}

func invalid(err error) error { return status.Error(codes.InvalidArgument, err.Error()) }

// CreateCA creates a dedicated CA and a signing certificate; the CA key is
// kept, encrypted with the same passphrase, to renew the certificate.
func (s *Service) CreateCA(_ context.Context, req *openrmmv1.CreateCARequest) (*openrmmv1.BuilderStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkPassphrase(req.GetPassphrase()); err != nil {
		return nil, err
	}
	now := s.now()
	ca, err := codesign.NewCA(subjectOf(req.GetSubject()), now)
	if err != nil {
		return nil, invalid(err)
	}
	leaf, err := ca.Issue(subjectOf(req.GetSubject()), now)
	if err != nil {
		return nil, invalid(err)
	}
	caKey, err := codesign.EncryptKeyPEM(ca.Key, req.GetPassphrase())
	if err != nil {
		return nil, invalid(err)
	}
	leafKey, err := codesign.EncryptKeyPEM(leaf.Key, req.GetPassphrase())
	if err != nil {
		return nil, invalid(err)
	}
	if err := s.archive(); err != nil {
		return nil, err
	}
	for _, f := range []struct {
		name string
		data []byte
	}{{fileCAKey, caKey}, {fileCACert, pki.EncodeCertPEM(ca.Cert)}, {fileKey, leafKey}, {fileChain, pki.EncodeCertPEM(leaf.Cert, ca.Cert)}} {
		if err := s.write(f.name, f.data); err != nil {
			return nil, err
		}
	}
	s.Log.Info("dedicated code-signing CA created", "subject", leaf.Cert.Subject.String(), "not_after", leaf.Cert.NotAfter)
	return s.status()
}

// CreateRequest creates a key and a certificate request.
func (s *Service) CreateRequest(_ context.Context, req *openrmmv1.CreateRequestRequest) (*openrmmv1.BuilderStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkPassphrase(req.GetPassphrase()); err != nil {
		return nil, err
	}
	key, csr, err := codesign.NewRequest(subjectOf(req.GetSubject()))
	if err != nil {
		return nil, invalid(err)
	}
	enc, err := codesign.EncryptKeyPEM(key, req.GetPassphrase())
	if err != nil {
		return nil, invalid(err)
	}
	if err := s.write(fileRequestKey, enc); err != nil {
		return nil, err
	}
	if err := s.write(fileRequest, csr); err != nil {
		return nil, err
	}
	s.Log.Info("code-signing request created")
	return s.status()
}

// ImportCertificate completes the pending request with its certificate.
func (s *Service) ImportCertificate(_ context.Context, req *openrmmv1.ImportCertificateRequest) (*openrmmv1.BuilderStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	csrPEM, err := os.ReadFile(s.path(fileRequest))
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "no pending request")
	}
	b, _ := pem.Decode(csrPEM)
	if b == nil {
		return nil, status.Error(codes.FailedPrecondition, "pending request unreadable")
	}
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		return nil, err
	}
	ch, err := codesign.ParseChain([]byte(req.GetChainPem()), s.now())
	if err != nil {
		return nil, invalid(err)
	}
	a, _ := x509.MarshalPKIXPublicKey(ch.Leaf.PublicKey)
	c, _ := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if !bytes.Equal(a, c) {
		return nil, invalid(errors.New("the certificate was not issued for the pending request"))
	}
	if err := s.archive(); err != nil {
		return nil, err
	}
	if err := os.Rename(s.path(fileRequestKey), s.path(fileKey)); err != nil {
		return nil, err
	}
	if err := s.write(fileChain, pki.EncodeCertPEM(append([]*x509.Certificate{ch.Leaf}, ch.CAs...)...)); err != nil {
		return nil, err
	}
	_ = os.Remove(s.path(fileRequest))
	s.Log.Info("code-signing certificate imported", "subject", ch.Leaf.Subject.String(), "not_after", ch.Leaf.NotAfter)
	return s.status()
}

// Renew issues a new signing certificate with the dedicated CA.
func (s *Service) Renew(_ context.Context, req *openrmmv1.RenewRequest) (*openrmmv1.BuilderStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	keyPEM, err := os.ReadFile(s.path(fileCAKey))
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "no dedicated CA")
	}
	caKey, err := codesign.DecryptKeyPEM(keyPEM, req.GetPassphrase())
	if err != nil {
		return nil, status.Error(codes.PermissionDenied, err.Error())
	}
	caPEM, err := os.ReadFile(s.path(fileCACert))
	if err != nil {
		return nil, err
	}
	certs, err := pki.ParseCertsPEM(caPEM)
	if err != nil {
		return nil, err
	}
	chain, err := os.ReadFile(s.path(fileChain))
	if err != nil {
		return nil, err
	}
	cur, err := pki.ParseCertsPEM(chain)
	if err != nil {
		return nil, err
	}
	ca := &codesign.Material{Cert: certs[0], Key: caKey}
	sub := cur[0].Subject
	first := func(v []string) string {
		if len(v) > 0 {
			return v[0]
		}
		return ""
	}
	leaf, err := ca.Issue(codesign.Subject{CommonName: sub.CommonName, Organization: first(sub.Organization), Country: first(sub.Country),
		OrganizationalUnit: first(sub.OrganizationalUnit), Locality: first(sub.Locality), Province: first(sub.Province)}, s.now())
	if err != nil {
		return nil, err
	}
	enc, err := codesign.EncryptKeyPEM(leaf.Key, req.GetPassphrase())
	if err != nil {
		return nil, invalid(err)
	}
	if err := s.write(fileKey, enc); err != nil {
		return nil, err
	}
	if err := s.write(fileChain, pki.EncodeCertPEM(leaf.Cert, ca.Cert)); err != nil {
		return nil, err
	}
	s.Log.Info("code-signing certificate renewed", "not_after", leaf.Cert.NotAfter)
	return s.status()
}

// ImportPFX imports the key and chain of a PFX through OpenSSL; the key
// goes from OpenSSL's output pipe straight to its encrypted form.
func (s *Service) ImportPFX(ctx context.Context, req *openrmmv1.ImportPFXRequest) (*openrmmv1.BuilderStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkPassphrase(req.GetPassphrase()); err != nil {
		return nil, err
	}
	if len(req.GetPfx()) == 0 || len(req.GetPfx()) > 1<<20 {
		return nil, invalid(errors.New("invalid PFX"))
	}
	run := func(extra ...string) ([]byte, error) {
		args := append([]string{"pkcs12", "-in", "/dev/fd/3", "-passin", "fd:4"}, extra...)
		return runWithPipes(ctx, "openssl", args, "", req.GetPfx(), []byte(req.GetPfxPassword()+"\n"))
	}
	keyOut, err := run("-nocerts", "-nodes")
	if err != nil {
		keyOut, err = run("-nocerts", "-nodes", "-legacy")
	}
	if err != nil {
		return nil, invalid(errors.New("cannot open the PFX: wrong password or unsupported file"))
	}
	certOut, err := run("-nokeys")
	if err != nil {
		certOut, err = run("-nokeys", "-legacy")
	}
	if err != nil {
		return nil, invalid(errors.New("cannot read the PFX certificates"))
	}
	key, err := parsePlainKey(keyOut)
	for i := range keyOut {
		keyOut[i] = 0
	}
	if err != nil {
		return nil, invalid(err)
	}
	certs, err := pki.ParseCertsPEM(certOut)
	if err != nil {
		return nil, invalid(err)
	}
	// Leaf first: the certificate of the key.
	var ordered []*x509.Certificate
	for _, c := range certs {
		if codesign.MatchesKey(c, key) {
			ordered = append([]*x509.Certificate{c}, ordered...)
		} else {
			ordered = append(ordered, c)
		}
	}
	chainPEM := pki.EncodeCertPEM(ordered...)
	ch, err := codesign.ParseChain(chainPEM, s.now())
	if err != nil || !codesign.MatchesKey(ch.Leaf, key) {
		return nil, invalid(fmt.Errorf("the PFX does not hold a valid code-signing certificate with its key: %v", err))
	}
	enc, err := codesign.EncryptKeyPEM(key, req.GetPassphrase())
	if err != nil {
		return nil, invalid(err)
	}
	if err := s.archive(); err != nil {
		return nil, err
	}
	if err := s.write(fileKey, enc); err != nil {
		return nil, err
	}
	if err := s.write(fileChain, chainPEM); err != nil {
		return nil, err
	}
	s.Log.Info("code-signing PFX imported", "subject", ch.Leaf.Subject.String(), "not_after", ch.Leaf.NotAfter)
	return s.status()
}

func parsePlainKey(out []byte) (*rsa.PrivateKey, error) {
	for rest := out; ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			return nil, errors.New("no key in the PFX")
		}
		switch b.Type {
		case "PRIVATE KEY":
			k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
			if err != nil {
				return nil, err
			}
			if rk, ok := k.(*rsa.PrivateKey); ok {
				return rk, nil
			}
			return nil, errors.New("only RSA code-signing keys are supported")
		case "RSA PRIVATE KEY":
			return x509.ParsePKCS1PrivateKey(b.Bytes)
		}
	}
}

// runWithPipes runs a tool with data on file descriptors 3, 4… (pipes, so
// nothing lands on disk) and returns its standard output.
func runWithPipes(ctx context.Context, name string, args []string, dir string, fds ...[]byte) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...) // #nosec G204 -- fixed tools, arguments built here
	cmd.Dir = dir
	type feed struct {
		w    *os.File
		data []byte
	}
	var feeds []feed
	for _, data := range fds {
		r, w, err := os.Pipe()
		if err != nil {
			return nil, err
		}
		cmd.ExtraFiles = append(cmd.ExtraFiles, r)
		feeds = append(feeds, feed{w, data})
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Start(); err != nil {
		for i, f := range feeds {
			_ = f.w.Close()
			_ = cmd.ExtraFiles[i].Close()
		}
		return nil, err
	}
	for _, r := range cmd.ExtraFiles {
		_ = r.Close()
	}
	var wg sync.WaitGroup
	for _, f := range feeds {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = f.w.Write(f.data)
			_ = f.w.Close()
		}()
	}
	err := cmd.Wait()
	wg.Wait()
	if err != nil {
		return nil, fmt.Errorf("%s: %v: %s", name, err, strings.TrimSpace(lastLines(stderr.String(), 3)))
	}
	return stdout.Bytes(), nil
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}

// Build builds and signs an installer.
func (s *Service) Build(req *openrmmv1.BuildRequest, stream openrmmv1.BuilderService_BuildServer) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx := stream.Context()
	if !versionRe.MatchString(req.GetVersion()) {
		return invalid(errors.New("invalid version"))
	}
	if len(req.GetAgentExe()) == 0 || len(req.GetWatchdogExe()) == 0 ||
		len(req.GetAgentExe()) > MaxExecutable || len(req.GetWatchdogExe()) > MaxExecutable {
		return invalid(errors.New("missing or oversized executables"))
	}
	for k, v := range req.GetProperties() {
		re, ok := buildProperties[k]
		if !ok || len(v) > 8192 || !re.MatchString(v) {
			return invalid(fmt.Errorf("invalid property %s", k))
		}
	}
	ts := req.GetTimestampUrl()
	if ts != "" && !tsRe.MatchString(ts) {
		return invalid(errors.New("invalid timestamp server"))
	}
	keyPEM, err := os.ReadFile(s.path(fileKey))
	if err != nil {
		return status.Error(codes.FailedPrecondition, "no signing certificate")
	}
	// Check the passphrase first: a clear error instead of a tool failure.
	if _, err := codesign.DecryptKeyPEM(keyPEM, req.GetPassphrase()); err != nil {
		return status.Error(codes.PermissionDenied, err.Error())
	}
	chainPEM, err := os.ReadFile(s.path(fileChain))
	if err != nil {
		return err
	}
	if _, err := codesign.ParseChain(chainPEM, s.now()); err != nil {
		return status.Error(codes.FailedPrecondition, "signing certificate: "+err.Error())
	}
	work, err := os.MkdirTemp("", "build-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	bin := filepath.Join(work, "bin")
	if err := os.Mkdir(bin, 0o700); err != nil {
		return err
	}
	sign := func(path string) error {
		args := []string{"sign", "-certs", s.path(fileChain), "-key", s.path(fileKey), "-readpass", "/dev/fd/3",
			"-h", "sha256", "-n", "open-rmm agent", "-i", "https://github.com/stefanozanarini/open-rmm"}
		if ts != "" {
			args = append(args, "-ts", ts)
		}
		args = append(args, "-in", path, "-out", path+".signed")
		if _, err := runWithPipes(ctx, "osslsigncode", args, work, []byte(req.GetPassphrase())); err != nil {
			return err
		}
		return os.Rename(path+".signed", path)
	}
	for name, data := range map[string][]byte{"openrmm-agent.exe": req.GetAgentExe(), "openrmm-watchdog.exe": req.GetWatchdogExe()} {
		p := filepath.Join(bin, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			return err
		}
		if err := sign(p); err != nil {
			return status.Error(codes.Internal, "sign "+name+": "+err.Error())
		}
	}
	msi := filepath.Join(work, "openrmm-agent.msi")
	if _, err := runWithPipes(ctx, "wixl", []string{"-a", "x64", "-D", "Version=" + req.GetVersion(), "-D", "BinDir=bin", "-o", msi, s.WXS}, work); err != nil {
		return status.Error(codes.Internal, err.Error())
	}
	if err := s.setProperties(ctx, msi, work, req.GetProperties()); err != nil {
		return status.Error(codes.Internal, err.Error())
	}
	if err := sign(msi); err != nil {
		return status.Error(codes.Internal, "sign MSI: "+err.Error())
	}
	f, err := os.Open(msi) // #nosec G304 -- built here
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	buf := make([]byte, chunkSize)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			h.Write(buf[:n])
			if serr := stream.Send(&openrmmv1.BuildChunk{Data: buf[:n]}); serr != nil {
				return serr
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
	}
	sum := hex.EncodeToString(h.Sum(nil))
	s.Log.Info("installer built", "version", req.GetVersion(), "sha256", sum)
	return stream.Send(&openrmmv1.BuildChunk{Sha256: sum})
}

// setProperties lets the configuration properties reach the elevated
// install (wixl cannot declare SecureCustomProperties) and presets them.
func (s *Service) setProperties(ctx context.Context, msi, work string, props map[string]string) error {
	out, err := runWithPipes(ctx, "msiinfo", []string{"export", msi, "Property"}, work)
	if err != nil {
		return err
	}
	cur := ""
	for _, line := range strings.Split(string(out), "\n") {
		if k, v, ok := strings.Cut(strings.TrimRight(line, "\r"), "\t"); ok && k == "SecureCustomProperties" {
			cur = v
		}
	}
	secure := "SERVER;ENROLLTOKEN;ROOTCA;JOBSIGNINGKEYS;MODULESIGNINGKEYS;RELEASESIGNINGKEYS;ALLOWADHOCSCRIPTS"
	if cur != "" {
		secure = cur + ";" + secure
	}
	// Values are checked against buildProperties: no quotes reach the SQL.
	queries := []string{"UPDATE Property SET Value='" + secure + "' WHERE Property='SecureCustomProperties'"}
	for k, v := range props {
		queries = append(queries, "INSERT INTO Property (Property, Value) VALUES ('"+k+"', '"+v+"')")
	}
	for _, q := range queries {
		if _, err := runWithPipes(ctx, "msibuild", []string{msi, "-q", q}, work); err != nil {
			return err
		}
	}
	return nil
}
