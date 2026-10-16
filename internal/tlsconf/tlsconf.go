// Package tlsconf builds the TLS configurations shared by agent and gateway.
// Only TLS 1.3 is accepted.
package tlsconf

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
)

// Server returns the gateway configuration. Client certificates are verified
// against agentsCA when presented; RPCs other than enrollment additionally
// require one (enforced by the gateway interceptors).
func Server(cert *x509.Certificate, chain []*x509.Certificate, key crypto.Signer, agentsCA *x509.Certificate) *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(agentsCA)
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{leaf(cert, chain, key)},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    pool,
		NextProtos:   []string{"h2"},
	}
}

// Client returns the agent configuration. The server must chain to the pinned
// root; the system trust store is never consulted.
func Client(serverName string, root *x509.Certificate, cert *x509.Certificate, chain []*x509.Certificate, key crypto.Signer) *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(root)
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    pool,
		ServerName: serverName,
		NextProtos: []string{"h2"},
	}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{leaf(cert, chain, key)}
	}
	return cfg
}

func leaf(cert *x509.Certificate, chain []*x509.Certificate, key crypto.Signer) tls.Certificate {
	raw := [][]byte{cert.Raw}
	for _, c := range chain {
		raw = append(raw, c.Raw)
	}
	return tls.Certificate{Certificate: raw, PrivateKey: key, Leaf: cert}
}
