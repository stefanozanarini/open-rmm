// Package identity manages the agent key pair and certificate.
//
// The private key is generated on the endpoint and never leaves it.
// TODO(fase 0): protect the key with the TPM, falling back to DPAPI.
package identity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/agent/secfile"
	"github.com/stefanozanarini/open-rmm/internal/pki"
)

const (
	stateFile = "identity.json"
	filesGlob = "agent-*"
)

var (
	// ErrNoIdentity means the agent has not enrolled yet.
	ErrNoIdentity = errors.New("agent not enrolled")
	// ErrExpired means the certificate expired before it could be renewed;
	// the agent must enroll again.
	ErrExpired = errors.New("agent certificate expired")
)

// Identity is the enrolled identity of this agent.
type Identity struct {
	TenantID string
	AgentID  string
	Key      crypto.Signer
	Cert     *x509.Certificate
	Chain    []*x509.Certificate // intermediates
}

// state is the identity index. Key and certificate live in versioned files
// it points to, so replacing them (renewal) is a single atomic rename of the
// index: a crash leaves either the old or the new identity, never a mix.
type state struct {
	TenantID string `json:"tenant_id"`
	AgentID  string `json:"agent_id"`
	KeyFile  string `json:"key_file"`
	CertFile string `json:"cert_file"`
}

// Load reads the identity from dir and checks that it is coherent and chains
// to root.
func Load(dir string, root *x509.Certificate) (*Identity, error) {
	raw, err := os.ReadFile(filepath.Join(dir, stateFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoIdentity
	}
	if err != nil {
		return nil, err
	}
	var st state
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, fmt.Errorf("identity state: %w", err)
	}
	if !validFileName(st.KeyFile) || !validFileName(st.CertFile) {
		return nil, errors.New("identity state: invalid file names")
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, st.KeyFile))
	if err != nil {
		return nil, err
	}
	key, err := pki.ParseKeyPEM(keyPEM)
	if err != nil {
		return nil, err
	}
	certPEM, err := os.ReadFile(filepath.Join(dir, st.CertFile))
	if err != nil {
		return nil, err
	}
	certs, err := pki.ParseCertsPEM(certPEM)
	if err != nil {
		return nil, err
	}
	id := &Identity{TenantID: st.TenantID, AgentID: st.AgentID, Key: key, Cert: certs[0], Chain: certs[1:]}
	if err := id.check(root, time.Now()); err != nil {
		return nil, err
	}
	return id, nil
}

// validFileName accepts only names produced by Save, so a tampered index
// cannot point the agent at files outside its data directory.
func validFileName(name string) bool {
	ok, _ := filepath.Match(filesGlob, name)
	return ok && filepath.Base(name) == name
}

// NeedsRenewal reports whether less than a third of the certificate validity
// is left.
func (id *Identity) NeedsRenewal(now time.Time) bool {
	lifetime := id.Cert.NotAfter.Sub(id.Cert.NotBefore)
	return id.Cert.NotAfter.Sub(now) < lifetime/3
}

func (id *Identity) check(root *x509.Certificate, now time.Time) error {
	if now.After(id.Cert.NotAfter) {
		return fmt.Errorf("%w on %s", ErrExpired, id.Cert.NotAfter.Format(time.RFC3339))
	}
	type equaler interface{ Equal(crypto.PublicKey) bool }
	if e, ok := id.Cert.PublicKey.(equaler); !ok || !e.Equal(id.Key.Public()) {
		return errors.New("certificate does not match private key")
	}
	got, err := pki.IdentityFromCert(id.Cert)
	if err != nil {
		return err
	}
	if got.TenantID != id.TenantID || got.AgentID != id.AgentID {
		return errors.New("certificate identity does not match state")
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	inter := x509.NewCertPool()
	for _, c := range id.Chain {
		inter.AddCert(c)
	}
	_, err = id.Cert.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: inter, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	return err
}

// NewKey generates the agent key pair.
func NewKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// CSR returns a DER certificate request for key. The CA ignores the subject;
// the hostname is included only to ease troubleshooting.
func CSR(key crypto.Signer, hostname string) ([]byte, error) {
	return x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: hostname},
	}, key)
}

// Save validates and stores a newly issued identity in dir.
func Save(dir string, root *x509.Certificate, id *Identity) error {
	if err := id.check(root, time.Now()); err != nil {
		return fmt.Errorf("issued certificate rejected: %w", err)
	}
	if err := secfile.EnsureDir(dir); err != nil {
		return err
	}
	keyPEM, err := pki.EncodeKeyPEM(id.Key)
	if err != nil {
		return err
	}
	version := time.Now().UTC().Format("20060102T150405.000000000Z")
	st := state{TenantID: id.TenantID, AgentID: id.AgentID,
		KeyFile: "agent-" + version + ".key", CertFile: "agent-" + version + ".crt"}
	raw, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if err := secfile.WriteFile(filepath.Join(dir, st.KeyFile), keyPEM); err != nil {
		return err
	}
	certs := append([]*x509.Certificate{id.Cert}, id.Chain...)
	if err := secfile.WriteFile(filepath.Join(dir, st.CertFile), pki.EncodeCertPEM(certs...)); err != nil {
		return err
	}
	// The index is replaced last: until this rename the old identity is
	// still the one in use.
	if err := secfile.WriteFile(filepath.Join(dir, stateFile), raw); err != nil {
		return err
	}
	removeStale(dir, st)
	return nil
}

// removeStale deletes key and certificate files no longer referenced.
func removeStale(dir string, keep state) {
	old, _ := filepath.Glob(filepath.Join(dir, filesGlob))
	for _, p := range old {
		if b := filepath.Base(p); b != keep.KeyFile && b != keep.CertFile {
			_ = os.Remove(p)
		}
	}
}
