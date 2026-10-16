// Package signing signs and verifies payloads with Ed25519.
//
// Every signature covers a domain-separation prefix plus the opaque payload
// bytes, so a signature produced for one purpose (e.g. a module manifest) can
// never be replayed as another (e.g. a job).
package signing

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Domain identifies what a signature is for.
type Domain string

const (
	DomainJob            Domain = "openrmm/job/v1"
	DomainModuleManifest Domain = "openrmm/module-manifest/v1"
	DomainAgentRelease   Domain = "openrmm/agent-release/v1"
)

// MaxPayload bounds the payload size accepted for verification.
const MaxPayload = 1 << 20

var (
	ErrUnknownKey   = errors.New("unknown signing key")
	ErrBadSignature = errors.New("invalid signature")
)

func message(d Domain, payload []byte) []byte {
	m := make([]byte, 0, len(d)+1+len(payload))
	m = append(m, d...)
	m = append(m, 0)
	return append(m, payload...)
}

// KeyID derives the identifier of a public key: the first 16 bytes of its
// SHA-256, hex encoded.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:16])
}

// Signer holds a private key.
type Signer struct {
	key ed25519.PrivateKey
	id  string
}

// NewSigner wraps an Ed25519 private key.
func NewSigner(key ed25519.PrivateKey) (*Signer, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid Ed25519 private key")
	}
	return &Signer{key: key, id: KeyID(key.Public().(ed25519.PublicKey))}, nil
}

// KeyID returns the signer's key identifier.
func (s *Signer) KeyID() string { return s.id }

// Sign signs payload for domain d.
func (s *Signer) Sign(d Domain, payload []byte) []byte {
	return ed25519.Sign(s.key, message(d, payload))
}

// Keyring is a set of trusted public keys, each allowed for specific domains.
type Keyring struct {
	keys map[string]trustedKey
}

type trustedKey struct {
	pub     ed25519.PublicKey
	domains map[Domain]bool
}

// NewKeyring returns an empty keyring.
func NewKeyring() *Keyring { return &Keyring{keys: map[string]trustedKey{}} }

// Add trusts pub for the given domains and returns its key ID.
func (k *Keyring) Add(pub ed25519.PublicKey, domains ...Domain) (string, error) {
	if len(pub) != ed25519.PublicKeySize {
		return "", errors.New("invalid Ed25519 public key")
	}
	if len(domains) == 0 {
		return "", errors.New("a trusted key needs at least one domain")
	}
	id := KeyID(pub)
	tk := trustedKey{pub: append(ed25519.PublicKey(nil), pub...), domains: map[Domain]bool{}}
	for _, d := range domains {
		tk.domains[d] = true
	}
	k.keys[id] = tk
	return id, nil
}

// Len returns the number of trusted keys.
func (k *Keyring) Len() int { return len(k.keys) }

// Verify checks that signature is valid for payload under domain d with the
// key identified by keyID.
func (k *Keyring) Verify(d Domain, keyID string, payload, signature []byte) error {
	if len(payload) > MaxPayload {
		return fmt.Errorf("%w: payload too large", ErrBadSignature)
	}
	tk, ok := k.keys[keyID]
	if !ok || !tk.domains[d] {
		return ErrUnknownKey
	}
	if len(signature) != ed25519.SignatureSize || !ed25519.Verify(tk.pub, message(d, payload), signature) {
		return ErrBadSignature
	}
	return nil
}

// EncodePublicKey renders a public key as "ed25519:<base64>".
func EncodePublicKey(pub ed25519.PublicKey) string {
	return "ed25519:" + base64.StdEncoding.EncodeToString(pub)
}

// ParsePublicKey parses the format produced by EncodePublicKey.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(s), "ed25519:")
	if !ok {
		return nil, errors.New(`public key must start with "ed25519:"`)
	}
	b, err := base64.StdEncoding.DecodeString(rest)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("invalid Ed25519 public key encoding")
	}
	return ed25519.PublicKey(b), nil
}

// EncodePrivateKey renders a private key seed as "ed25519-seed:<base64>".
func EncodePrivateKey(key ed25519.PrivateKey) string {
	return "ed25519-seed:" + base64.StdEncoding.EncodeToString(key.Seed())
}

// ParsePrivateKey parses the format produced by EncodePrivateKey.
func ParsePrivateKey(s string) (ed25519.PrivateKey, error) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(s), "ed25519-seed:")
	if !ok {
		return nil, errors.New(`private key must start with "ed25519-seed:"`)
	}
	b, err := base64.StdEncoding.DecodeString(rest)
	if err != nil || len(b) != ed25519.SeedSize {
		return nil, errors.New("invalid Ed25519 seed encoding")
	}
	return ed25519.NewKeyFromSeed(b), nil
}
