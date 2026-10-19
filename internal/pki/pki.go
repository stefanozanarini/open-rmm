// Package pki implements the open-rmm certificate hierarchy:
//
//	root CA (kept offline, pinned by every agent)
//	└── agents CA (online on the gateway)
//	    ├── gateway server certificate
//	    └── agent client certificates
//
// Agent identity is carried in a URI SAN of the form
// openrmm://tenants/<tenant-id>/agents/<agent-id>.
package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/ids"
)

const (
	RootValidity      = 20 * 365 * 24 * time.Hour
	AgentsCAValidity  = 5 * 365 * 24 * time.Hour
	ServerValidity    = 397 * 24 * time.Hour
	AgentCertValidity = 90 * 24 * time.Hour

	// clockSkew backdates NotBefore so endpoints with a slightly wrong clock
	// accept freshly issued certificates.
	clockSkew = 5 * time.Minute

	uriScheme = "openrmm"
)

// Identity is the authenticated identity of an agent.
type Identity struct {
	TenantID string
	AgentID  string
}

// URI returns the SAN URI that encodes the identity.
func (id Identity) URI() *url.URL {
	return &url.URL{Scheme: uriScheme, Host: "tenants", Path: "/" + id.TenantID + "/agents/" + id.AgentID}
}

// IdentityFromCert extracts the agent identity from a certificate that has
// already been verified against the agents CA.
func IdentityFromCert(c *x509.Certificate) (Identity, error) {
	var found []Identity
	for _, u := range c.URIs {
		if u.Scheme != uriScheme || u.Host != "tenants" {
			continue
		}
		parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
		if len(parts) != 3 || parts[1] != "agents" || !ids.IsUUID(parts[0]) || !ids.IsUUID(parts[2]) {
			return Identity{}, fmt.Errorf("malformed identity URI %q", u.String())
		}
		found = append(found, Identity{TenantID: parts[0], AgentID: parts[2]})
	}
	if len(found) != 1 {
		return Identity{}, fmt.Errorf("certificate must carry exactly one identity URI, found %d", len(found))
	}
	return found[0], nil
}

// coreURI marks the client certificate of the internal core, used to open
// the tunnels to the gateway. It is distinct from any agent identity.
const coreURI = "openrmm://core"

// IsCore reports whether c is a core certificate (already verified).
func IsCore(c *x509.Certificate) bool {
	if len(c.URIs) != 1 || c.URIs[0].String() != coreURI {
		return false
	}
	for _, u := range c.ExtKeyUsage {
		if u == x509.ExtKeyUsageClientAuth {
			return true
		}
	}
	return false
}

// IssueCore issues the core's tunnel client certificate.
func (ca *CA) IssueCore(now time.Time) (*x509.Certificate, crypto.Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	u, _ := url.Parse(coreURI)
	tmpl := &x509.Certificate{
		Subject:        pkix.Name{CommonName: "open-rmm core", Organization: []string{"open-rmm"}},
		URIs:           []*url.URL{u},
		NotBefore:      now.Add(-clockSkew),
		NotAfter:       minTime(now.Add(ServerValidity), ca.Cert.NotAfter),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		AuthorityKeyId: ca.Cert.SubjectKeyId,
	}
	cert, err := create(tmpl, ca, key.Public(), nil)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

// CA is a certificate authority with its signing key.
type CA struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}

func newSerial() *big.Int {
	// 128 random bits, positive.
	return new(big.Int).SetBytes(ids.Random(16))
}

func keyID(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(der)
	return sum[:20], nil
}

func create(tmpl *x509.Certificate, parent *CA, pub crypto.PublicKey, selfKey crypto.Signer) (*x509.Certificate, error) {
	skid, err := keyID(pub)
	if err != nil {
		return nil, err
	}
	tmpl.SubjectKeyId = skid
	tmpl.SerialNumber = newSerial()
	parentCert, signer := tmpl, selfKey
	if parent != nil {
		parentCert, signer = parent.Cert, parent.Key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, pub, signer)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// NewRootCA creates a self-signed root CA with an ECDSA P-384 key.
func NewRootCA(commonName string, now time.Time) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"open-rmm"}},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(RootValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	cert, err := create(tmpl, nil, key.Public(), key)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key}, nil
}

// NewIntermediateCA creates the agents CA, signed by root. It may only issue
// end-entity certificates.
func NewIntermediateCA(root *CA, commonName string, now time.Time) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"open-rmm"}},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              minTime(now.Add(AgentsCAValidity), root.Cert.NotAfter),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		AuthorityKeyId:        root.Cert.SubjectKeyId,
	}
	cert, err := create(tmpl, root, key.Public(), nil)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key}, nil
}

// IssueServer issues a TLS server certificate for the given DNS names.
func (ca *CA) IssueServer(dnsNames []string, now time.Time) (*x509.Certificate, crypto.Signer, error) {
	if len(dnsNames) == 0 {
		return nil, nil, errors.New("at least one DNS name is required")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		Subject:        pkix.Name{CommonName: dnsNames[0], Organization: []string{"open-rmm"}},
		DNSNames:       dnsNames,
		NotBefore:      now.Add(-clockSkew),
		NotAfter:       minTime(now.Add(ServerValidity), ca.Cert.NotAfter),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		AuthorityKeyId: ca.Cert.SubjectKeyId,
	}
	cert, err := create(tmpl, ca, key.Public(), nil)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

// ErrBadCSR is returned when a certificate signing request is rejected.
var ErrBadCSR = errors.New("invalid certificate signing request")

// IssueAgent validates a CSR generated by an agent and issues its client
// certificate. Only the public key is taken from the CSR: subject and SANs
// are set exclusively by the CA.
func (ca *CA) IssueAgent(csrDER []byte, id Identity, now time.Time) (*x509.Certificate, error) {
	if len(csrDER) == 0 || len(csrDER) > 8192 {
		return nil, ErrBadCSR
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadCSR, err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("%w: signature: %v", ErrBadCSR, err)
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: key must be ECDSA P-256", ErrBadCSR)
	}
	if !ids.IsUUID(id.TenantID) || !ids.IsUUID(id.AgentID) {
		return nil, errors.New("identity must use UUIDs")
	}
	tmpl := &x509.Certificate{
		Subject:        pkix.Name{CommonName: id.AgentID, Organization: []string{"open-rmm agent"}},
		URIs:           []*url.URL{id.URI()},
		NotBefore:      now.Add(-clockSkew),
		NotAfter:       minTime(now.Add(AgentCertValidity), ca.Cert.NotAfter),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		AuthorityKeyId: ca.Cert.SubjectKeyId,
	}
	return create(tmpl, ca, pub, nil)
}

// Fingerprint returns the hex SHA-256 of the certificate DER.
func Fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// EncodeCertPEM encodes certificates as concatenated PEM blocks.
func EncodeCertPEM(certs ...*x509.Certificate) []byte {
	var out []byte
	for _, c := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return out
}

// EncodeKeyPEM encodes a private key as PKCS#8 PEM.
func EncodeKeyPEM(key crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ParseCertsPEM parses every CERTIFICATE block in data.
func ParseCertsPEM(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, errors.New("no certificate found")
	}
	return certs, nil
}

// ParseKeyPEM parses a PKCS#8 PEM private key.
func ParseKeyPEM(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("no PKCS#8 private key found")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, errors.New("key is not a signer")
	}
	return s, nil
}

// LoadCA parses a CA certificate and key from PEM.
func LoadCA(certPEM, keyPEM []byte) (*CA, error) {
	certs, err := ParseCertsPEM(certPEM)
	if err != nil {
		return nil, err
	}
	key, err := ParseKeyPEM(keyPEM)
	if err != nil {
		return nil, err
	}
	if !certs[0].IsCA {
		return nil, errors.New("certificate is not a CA")
	}
	if !publicKeysEqual(certs[0].PublicKey, key.Public()) {
		return nil, errors.New("CA key does not match certificate")
	}
	return &CA{Cert: certs[0], Key: key}, nil
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	e, ok := a.(equaler)
	return ok && e.Equal(b)
}
