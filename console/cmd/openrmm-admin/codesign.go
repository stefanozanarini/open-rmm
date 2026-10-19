package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/codesign"
	"github.com/stefanozanarini/open-rmm/internal/pki"
)

func codesignSubject(fs *flag.FlagSet) func() codesign.Subject {
	org := fs.String("org", "", "organization shown as the publisher (e.g. \"Cliente Srl\")")
	cn := fs.String("cn", "", "common name (default: the organization)")
	country := fs.String("country", "", "two-letter country code (optional)")
	return func() codesign.Subject {
		return codesign.Subject{Organization: *org, CommonName: *cn, Country: *country}
	}
}

// codesignCA creates a dedicated code-signing CA and a signing certificate.
// The CA key is needed only to renew the signing certificate: keep it
// offline.
func codesignCA(args []string) error {
	fs := flag.NewFlagSet("codesign ca", flag.ContinueOnError)
	dir := fs.String("dir", "", "output directory (files must not exist)")
	subject := codesignSubject(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" {
		return errors.New("-dir is required")
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return err
	}
	now := time.Now()
	ca, err := codesign.NewCA(subject(), now)
	if err != nil {
		return err
	}
	leaf, err := ca.Issue(subject(), now)
	if err != nil {
		return err
	}
	caKey, err := pki.EncodeKeyPEM(ca.Key)
	if err != nil {
		return err
	}
	leafKey, err := pki.EncodeKeyPEM(leaf.Key)
	if err != nil {
		return err
	}
	files := []struct {
		name string
		data []byte
	}{
		{"codesign-ca.key", caKey},
		{"codesign-ca.crt", pki.EncodeCertPEM(ca.Cert)},
		{"codesign-ca.cer", ca.Cert.Raw},
		{"codesign.key", leafKey},
		{"codesign.crt", pki.EncodeCertPEM(leaf.Cert, ca.Cert)},
		{"codesign.cer", leaf.Cert.Raw},
	}
	for _, f := range files {
		if err := writeNew(filepath.Join(*dir, f.name), f.data); err != nil {
			return err
		}
	}
	fmt.Printf(`Created in %s:
  codesign.key / codesign.crt   signing key and certificate (with the CA) for make msi SIGN_KEY=… SIGN_CERT=…
  codesign-ca.cer               GPO: Computer Configuration → Windows Settings → Security Settings →
                                Public Key Policies → Trusted Root Certification Authorities
  codesign.cer                  GPO: … Public Key Policies → Trusted Publishers
  codesign-ca.key               needed only to renew the signing certificate: move it OFFLINE now

Paste codesign.crt in the console (Configurazione → Firma del codice) to publish the
certificates for download and get a warning before they expire (%s).
`, *dir, leaf.Cert.NotAfter.Format("2006-01-02"))
	return nil
}

// codesignCSR creates a key and a request for an enterprise (AD CS) or
// public CA.
func codesignCSR(args []string) error {
	fs := flag.NewFlagSet("codesign csr", flag.ContinueOnError)
	dir := fs.String("dir", "", "output directory (files must not exist)")
	subject := codesignSubject(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" {
		return errors.New("-dir is required")
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return err
	}
	key, csr, err := codesign.NewRequest(subject())
	if err != nil {
		return err
	}
	keyPEM, err := pki.EncodeKeyPEM(key)
	if err != nil {
		return err
	}
	if err := writeNew(filepath.Join(*dir, "codesign.key"), keyPEM); err != nil {
		return err
	}
	if err := writeNew(filepath.Join(*dir, "codesign.csr"), csr); err != nil {
		return err
	}
	fmt.Printf(`Created %s/codesign.key and codesign.csr.

Enterprise CA (AD CS), on a domain computer, with the "Code Signing" template
enabled and enroll permission for your account:
  certreq -submit -attrib "CertificateTemplate:CodeSigning" codesign.csr codesign.cer
  certutil -encode codesign.cer codesign.crt
Append the issuing and root CA certificates (PEM) to codesign.crt, then check it:
  openrmm-admin codesign check -cert codesign.crt -key codesign.key
Public CA: send codesign.csr to the CA and save what it returns as codesign.crt.
`, *dir)
	return nil
}

// codesignCheck verifies a certificate (and optionally its key) before use.
func codesignCheck(args []string) error {
	fs := flag.NewFlagSet("codesign check", flag.ContinueOnError)
	certFile := fs.String("cert", "", "PEM certificate, leaf first, then its CAs")
	keyFile := fs.String("key", "", "PKCS#8 PEM key (optional)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *certFile == "" {
		return errors.New("-cert is required")
	}
	data, err := os.ReadFile(*certFile) // #nosec G304 -- path chosen by the operator
	if err != nil {
		return err
	}
	ch, err := codesign.ParseChain(data, time.Now())
	if err != nil {
		return err
	}
	if *keyFile != "" {
		raw, err := os.ReadFile(*keyFile) // #nosec G304 -- path chosen by the operator
		if err != nil {
			return err
		}
		key, err := pki.ParseKeyPEM(raw)
		if err != nil {
			return err
		}
		if !codesign.MatchesKey(ch.Leaf, key) {
			return errors.New("the key does not belong to the certificate")
		}
	}
	i := ch.LeafInfo()
	fmt.Printf("subject:    %s\nissuer:     %s\nvalid:      %s – %s\nthumbprint: %s\nCAs:        %d\n",
		i.Subject, i.Issuer, i.NotBefore.Format("2006-01-02"), i.NotAfter.Format("2006-01-02"), i.Thumbprint, len(ch.CAs))
	if ch.Expiring(time.Now()) {
		fmt.Println("warning: the certificate expires within 60 days")
	}
	return nil
}
