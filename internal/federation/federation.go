// Package federation links customer consoles to a central console.
//
// The customer console opens the link: it dials the central console's link
// listener (outbound only, no inbound port at the customer) over TLS 1.3
// with pinned certificates on both sides, and keeps a few tunnels open. On
// the tunnels the roles are reversed: the central console is the HTTP
// client and the customer console serves its own web console, so every
// operation of the customer console is available centrally, with the
// customer's own checks and audit.
//
// Enrollment: the central console creates a link and shows a one-time
// token bundle (link address, pinned certificate, secret). The customer
// console creates its own key and certificate, dials with them and presents
// the secret once; from then on the central console knows the link by the
// customer's certificate fingerprint.
//
// Commands still need the customer's signer, which must be configured to
// trust the central console's directory (see authn.FederationFromEnv).
package federation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/ids"
	"github.com/stefanozanarini/open-rmm/internal/pki"
)

const (
	// Paths served on the tunnels by the customer console, outside its
	// normal web routes.
	PathSummary  = "/_federation/summary"
	PathCallback = "/_federation/callback"
	// pathEnroll is served by the central console to unknown certificates.
	pathEnroll = "/enroll"

	// HeaderOperator carries the central operator on each tunnel request.
	HeaderOperator = "Openrmm-Federation-Operator"

	// TokenTTL is how long a link token can be used.
	TokenTTL = 24 * time.Hour

	identityValidity = 10 * 365 * 24 * time.Hour
	bundlePrefix     = "ormm-link-1."
)

// Identity is a self-signed certificate used on links, recognized by its
// fingerprint (pinned) rather than by a CA.
type Identity struct {
	Cert        tls.Certificate
	Fingerprint string
	CertPEM     string
	KeyPEM      string
}

// Fingerprint returns the hex SHA-256 of a DER certificate.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// NewIdentity creates a key and a self-signed certificate.
func NewIdentity(name string, now time.Time) (*Identity, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: new(big.Int).SetBytes(ids.Random(16)),
		Subject:      pkix.Name{CommonName: "open-rmm federation " + name},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(identityValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	keyPEM, err := pki.EncodeKeyPEM(key)
	if err != nil {
		return nil, err
	}
	return LoadIdentity(string(pki.EncodeCertPEM(c)), string(keyPEM))
}

// LoadIdentity parses a stored identity.
func LoadIdentity(certPEM, keyPEM string) (*Identity, error) {
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, err
	}
	return &Identity{Cert: cert, Fingerprint: Fingerprint(cert.Certificate[0]), CertPEM: certPEM, KeyPEM: keyPEM}, nil
}

// pinned verifies that the peer presented exactly the certificate with
// fingerprint fp.
func pinned(fp string) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 || Fingerprint(cs.PeerCertificates[0].Raw) != fp {
			return errors.New("federation peer certificate does not match the pinned one")
		}
		return nil
	}
}

// Bundle is what the central console gives to the customer console's
// administrator to create a link.
type Bundle struct {
	Addr        string `json:"addr"`        // host:port of the central link listener
	Fingerprint string `json:"fingerprint"` // of the central console's link certificate
	Token       string `json:"token"`
}

var fpRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Encode returns the bundle as one line to copy and paste.
func (b Bundle) Encode() string {
	raw, _ := json.Marshal(b)
	return bundlePrefix + base64.RawURLEncoding.EncodeToString(raw)
}

// ParseBundle parses and checks a pasted bundle.
func ParseBundle(s string) (Bundle, error) {
	var b Bundle
	enc, ok := strings.CutPrefix(strings.TrimSpace(s), bundlePrefix)
	if !ok {
		return b, errors.New("not an open-rmm link token")
	}
	raw, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return b, errors.New("link token damaged")
	}
	if err := json.Unmarshal(raw, &b); err != nil {
		return b, errors.New("link token damaged")
	}
	host, port, err := net.SplitHostPort(b.Addr)
	if err != nil || host == "" || port == "" || !fpRe.MatchString(b.Fingerprint) || len(b.Token) < 32 || len(b.Token) > 128 {
		return b, errors.New("link token incomplete")
	}
	return b, nil
}

// Operator is the central operator a tunnel request is made for. The
// customer console trusts it because it comes over the authenticated link,
// caps its roles and keeps a separate session per central session.
type Operator struct {
	ObjectID string   `json:"oid"`
	TenantID string   `json:"tid"` // Entra tenant of the central directory
	Name     string   `json:"name"`
	Username string   `json:"username"`
	Roles    []string `json:"roles"`
	Session  string   `json:"session"` // random per central session
	Lang     string   `json:"lang,omitempty"`
	Theme    string   `json:"theme,omitempty"`
}

// Encode returns the header value.
func (o Operator) Encode() string {
	raw, _ := json.Marshal(o)
	return base64.RawURLEncoding.EncodeToString(raw)
}

// ParseOperator parses the header value.
func ParseOperator(v string) (Operator, error) {
	var o Operator
	raw, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil || len(raw) > 8<<10 {
		return o, errors.New("invalid operator header")
	}
	if err := json.Unmarshal(raw, &o); err != nil {
		return o, errors.New("invalid operator header")
	}
	if !ids.IsUUID(o.ObjectID) || !ids.IsUUID(o.TenantID) || len(o.Session) < 32 || len(o.Session) > 128 {
		return o, errors.New("incomplete operator header")
	}
	return o, nil
}

// Summary is what a customer console reports for the central dashboard.
type Summary struct {
	Console     string    `json:"console"` // tenant name at the customer
	Agents      int       `json:"agents"`
	Online      int       `json:"online"`
	Pending     int       `json:"pending"`
	OpenAlerts  int       `json:"open_alerts"`
	Critical    int       `json:"critical"` // open critical alerts
	MissingSec  int       `json:"missing_security"`
	Reboot      int       `json:"reboot_pending"`
	Version     string    `json:"version,omitempty"`
	GeneratedAt time.Time `json:"generated_at"`
}

func errorf(format string, a ...any) error { return fmt.Errorf("federation: "+format, a...) }
