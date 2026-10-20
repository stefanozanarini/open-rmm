// Package codesign creates and checks the Authenticode code-signing
// material used to sign the agent's executables and MSI.
//
// Keys are created by openrmm-admin on the machine that builds the MSI,
// never by the console: the console only keeps the public certificates, to
// offer them for Group Policy distribution and to warn before they expire.
package codesign

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 -- Windows certificate thumbprint, an identifier only
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/ids"
)

const (
	// RSA keys: Windows Installer and older Windows releases do not all
	// accept ECDSA Authenticode signatures.
	keyBits = 3072

	CAValidity      = 10 * 365 * 24 * time.Hour
	SigningValidity = 3 * 365 * 24 * time.Hour
	clockSkew       = 5 * time.Minute

	// ExpiryWarning is how long before expiry the console warns.
	ExpiryWarning = 60 * 24 * time.Hour
)

// Subject of the certificates: Windows shows the organization as the
// publisher.
type Subject struct {
	Organization       string
	CommonName         string // defaults to Organization
	Country            string // optional, two letters
	OrganizationalUnit string // optional
	Locality           string // optional
	Province           string // optional
}

func (s Subject) name(suffix string) (pkix.Name, error) {
	org := strings.TrimSpace(s.Organization)
	if org == "" || len(org) > 64 {
		return pkix.Name{}, errors.New("organization must have 1 to 64 characters")
	}
	cn := strings.TrimSpace(s.CommonName)
	if cn == "" {
		cn = org
	}
	if len(cn)+len(suffix) > 64 {
		return pkix.Name{}, errors.New("common name too long")
	}
	n := pkix.Name{CommonName: cn + suffix, Organization: []string{org}}
	for _, f := range []struct {
		v   string
		dst *[]string
	}{{s.OrganizationalUnit, &n.OrganizationalUnit}, {s.Locality, &n.Locality}, {s.Province, &n.Province}} {
		v := strings.TrimSpace(f.v)
		if len(v) > 64 {
			return pkix.Name{}, errors.New("subject fields have at most 64 characters")
		}
		if v != "" {
			*f.dst = []string{v}
		}
	}
	if s.Country != "" {
		if len(s.Country) != 2 {
			return pkix.Name{}, errors.New("country must be a two-letter code")
		}
		n.Country = []string{strings.ToUpper(s.Country)}
	}
	return n, nil
}

func serial() *big.Int { return new(big.Int).SetBytes(ids.Random(16)) }

func keyID(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(der)
	return sum[:20], nil
}

// Material is a certificate with its key.
type Material struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}

// NewCA creates a dedicated, self-signed code-signing CA that can only issue
// end-entity certificates.
func NewCA(s Subject, now time.Time) (*Material, error) {
	name, err := s.name(" Code Signing CA")
	if err != nil {
		return nil, err
	}
	key, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return nil, err
	}
	skid, err := keyID(key.Public())
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               name,
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(CAValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
		SubjectKeyId:          skid,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Material{Cert: c, Key: key}, nil
}

// Issue creates a code-signing certificate signed by ca.
func (ca *Material) Issue(s Subject, now time.Time) (*Material, error) {
	name, err := s.name("")
	if err != nil {
		return nil, err
	}
	key, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return nil, err
	}
	skid, err := keyID(key.Public())
	if err != nil {
		return nil, err
	}
	notAfter := now.Add(SigningValidity)
	if notAfter.After(ca.Cert.NotAfter) {
		notAfter = ca.Cert.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               name,
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
		SubjectKeyId:          skid,
		AuthorityKeyId:        ca.Cert.SubjectKeyId,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, key.Public(), ca.Key)
	if err != nil {
		return nil, err
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Material{Cert: c, Key: key}, nil
}

// NewRequest creates a key and a certificate request for an enterprise CA
// (AD CS "Code Signing" template) or a public CA.
func NewRequest(s Subject) (crypto.Signer, []byte, error) {
	name, err := s.name("")
	if err != nil {
		return nil, nil, err
	}
	key, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: name}, key)
	if err != nil {
		return nil, nil, err
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// Info describes a code-signing certificate for display.
type Info struct {
	Subject    string
	Issuer     string
	NotBefore  time.Time
	NotAfter   time.Time
	Thumbprint string // SHA-1, as Windows shows it
	SelfSigned bool
}

func info(c *x509.Certificate) Info {
	sum := sha1.Sum(c.Raw) // #nosec G401 -- thumbprint, not a security decision
	return Info{Subject: c.Subject.String(), Issuer: c.Issuer.String(), NotBefore: c.NotBefore, NotAfter: c.NotAfter,
		Thumbprint: strings.ToUpper(hex.EncodeToString(sum[:])), SelfSigned: c.CheckSignatureFrom(c) == nil}
}

// Chain is a parsed code-signing certificate with the CA certificates that
// came with it.
type Chain struct {
	Leaf *x509.Certificate
	CAs  []*x509.Certificate
}

// LeafInfo describes the signing certificate.
func (c Chain) LeafInfo() Info { return info(c.Leaf) }

// Root returns the self-signed CA of the chain, if it was included (to be
// distributed as a trusted root for a dedicated or enterprise CA).
func (c Chain) Root() *x509.Certificate {
	for _, ca := range c.CAs {
		if ca.CheckSignatureFrom(ca) == nil {
			return ca
		}
	}
	return nil
}

// Expiring tells whether the signing certificate expires within
// ExpiryWarning of now.
func (c Chain) Expiring(now time.Time) bool { return now.Add(ExpiryWarning).After(c.Leaf.NotAfter) }

// MaxPEM bounds what the console accepts.
const MaxPEM = 64 << 10

// ParseChain parses PEM certificates (leaf first, CAs in any order) and
// checks that the leaf is a code-signing certificate chaining to the CAs
// given, if any.
func ParseChain(pemData []byte, now time.Time) (Chain, error) {
	if len(pemData) > MaxPEM {
		return Chain{}, errors.New("certificate data too large")
	}
	var certs []*x509.Certificate
	rest := pemData
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			return Chain{}, fmt.Errorf("unexpected PEM block %q: give certificates only, never a key", b.Type)
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return Chain{}, err
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return Chain{}, errors.New("no PEM certificate found")
	}
	if len(certs) > 5 {
		return Chain{}, errors.New("too many certificates")
	}
	ch := Chain{Leaf: certs[0], CAs: certs[1:]}
	if err := CheckSigning(ch.Leaf, now); err != nil {
		return Chain{}, err
	}
	for _, ca := range ch.CAs {
		if !ca.IsCA {
			return Chain{}, fmt.Errorf("%s is not a CA certificate", ca.Subject)
		}
	}
	if len(ch.CAs) > 0 {
		roots, inter := x509.NewCertPool(), x509.NewCertPool()
		for _, ca := range ch.CAs {
			if ca.CheckSignatureFrom(ca) == nil {
				roots.AddCert(ca)
			} else {
				inter.AddCert(ca)
			}
		}
		if _, err := ch.Leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: now,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}); err != nil && ch.Root() != nil {
			return Chain{}, fmt.Errorf("the certificate does not chain to the CA given: %w", err)
		}
	}
	return ch, nil
}

// CheckSigning checks that c can sign code: code-signing usage, not a CA,
// valid now, and a strong enough key.
func CheckSigning(c *x509.Certificate, now time.Time) error {
	if c.IsCA {
		return errors.New("this is a CA certificate, not a code-signing certificate")
	}
	ok := false
	for _, u := range c.ExtKeyUsage {
		if u == x509.ExtKeyUsageCodeSigning {
			ok = true
		}
	}
	if !ok {
		return errors.New("the certificate is not valid for code signing (extended key usage)")
	}
	if c.KeyUsage != 0 && c.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return errors.New("the certificate key usage does not allow digital signatures")
	}
	if now.Before(c.NotBefore) || now.After(c.NotAfter) {
		return fmt.Errorf("the certificate is not valid now (%s – %s)", c.NotBefore.Format("2006-01-02"), c.NotAfter.Format("2006-01-02"))
	}
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return errors.New("RSA key shorter than 2048 bits")
		}
	case *ecdsa.PublicKey:
	default:
		return errors.New("unsupported key type")
	}
	return nil
}

// MatchesKey tells whether key is the private key of c.
func MatchesKey(c *x509.Certificate, key crypto.Signer) bool {
	a, err1 := x509.MarshalPKIXPublicKey(c.PublicKey)
	b, err2 := x509.MarshalPKIXPublicKey(key.Public())
	return err1 == nil && err2 == nil && string(a) == string(b)
}
