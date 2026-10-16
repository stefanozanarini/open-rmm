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
	keyFile   = "agent.key"
	certFile  = "agent.crt"
	stateFile = "identity.json"
)

// ErrNoIdentity means the agent has not enrolled yet.
var ErrNoIdentity = errors.New("agent not enrolled")

// Identity is the enrolled identity of this agent.
type Identity struct {
	TenantID string
	AgentID  string
	Key      crypto.Signer
	Cert     *x509.Certificate
	Chain    []*x509.Certificate // intermediates
}

type state struct {
	TenantID string `json:"tenant_id"`
	AgentID  string `json:"agent_id"`
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
	keyPEM, err := os.ReadFile(filepath.Join(dir, keyFile))
	if err != nil {
		return nil, err
	}
	key, err := pki.ParseKeyPEM(keyPEM)
	if err != nil {
		return nil, err
	}
	certPEM, err := os.ReadFile(filepath.Join(dir, certFile))
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

func (id *Identity) check(root *x509.Certificate, now time.Time) error {
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
	st, err := json.Marshal(state{TenantID: id.TenantID, AgentID: id.AgentID})
	if err != nil {
		return err
	}
	// The state file is written last: its presence marks a complete identity.
	if err := secfile.WriteFile(filepath.Join(dir, keyFile), keyPEM); err != nil {
		return err
	}
	certs := append([]*x509.Certificate{id.Cert}, id.Chain...)
	if err := secfile.WriteFile(filepath.Join(dir, certFile), pki.EncodeCertPEM(certs...)); err != nil {
		return err
	}
	return secfile.WriteFile(filepath.Join(dir, stateFile), st)
}
