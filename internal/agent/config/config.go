// Package config loads the agent configuration.
//
// Sources, from lowest to highest precedence:
//  1. the JSON file (agent.json),
//  2. on Windows, HKLM\SOFTWARE\open-rmm (written by the MSI),
//  3. on Windows, HKLM\SOFTWARE\Policies\open-rmm (written by GPO).
//
// Values set by policy cannot be changed by the console: they are the local
// guard rails described in the architecture document (§6.4).
package config

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/stefanozanarini/open-rmm/internal/pki"
	"github.com/stefanozanarini/open-rmm/internal/signing"
)

// Config is the effective agent configuration.
type Config struct {
	// Server is host:port of the agents endpoint, e.g. agent.example.com:443.
	Server string `json:"server"`
	// RootCAFile or RootCAPEM holds the pinned open-rmm root certificate.
	RootCAFile string `json:"root_ca_file,omitempty"`
	RootCAPEM  string `json:"root_ca_pem,omitempty"`
	// EnrollToken is used only until the agent has an identity.
	EnrollToken string `json:"enroll_token,omitempty"`
	// JobSigningKeys lists the trusted job signing public keys ("ed25519:...").
	JobSigningKeys []string `json:"job_signing_keys,omitempty"`
	// ModuleSigningKeys lists the trusted module release keys ("ed25519:...").
	ModuleSigningKeys []string `json:"module_signing_keys,omitempty"`
	// MaxConcurrentJobs is a local policy (default 4, at most 32).
	MaxConcurrentJobs int `json:"max_concurrent_jobs,omitempty"`
	// DataDir holds keys, certificates and state.
	DataDir string `json:"data_dir,omitempty"`
	// InstallDir holds the installed versions (InstallDir/versions/x.y.z).
	InstallDir string `json:"install_dir,omitempty"`
	// ReleaseSigningKeys lists the trusted agent release keys ("ed25519:...").
	ReleaseSigningKeys []string `json:"release_signing_keys,omitempty"`
	// AllowAdHocScripts is a local policy; default true (architecture §6.4).
	AllowAdHocScripts *bool `json:"allow_adhoc_scripts,omitempty"`
	// AllowInteractiveShell is a local policy; default true (each session
	// still needs an operator's MFA approval). Set it to false on endpoints
	// that must never accept one (GPO).
	AllowInteractiveShell *bool `json:"allow_interactive_shell,omitempty"`

	root        *x509.Certificate
	keys        *signing.Keyring
	moduleKeys  *signing.Keyring
	releaseKeys *signing.Keyring
}

// Load reads the file at path (which may be missing when the registry
// provides everything) and overlays OS-specific sources.
func Load(path string) (*Config, error) {
	c := &Config{}
	if path != "" {
		data, err := os.ReadFile(path)
		switch {
		case err == nil:
			dec := json.NewDecoder(strings.NewReader(string(data)))
			dec.DisallowUnknownFields()
			if err := dec.Decode(c); err != nil {
				return nil, fmt.Errorf("parse %s: %w", path, err)
			}
			if c.RootCAFile != "" && !filepath.IsAbs(c.RootCAFile) {
				c.RootCAFile = filepath.Join(filepath.Dir(path), c.RootCAFile)
			}
		case errors.Is(err, os.ErrNotExist):
		default:
			return nil, err
		}
	}
	if err := overlayOS(c); err != nil {
		return nil, err
	}
	if c.DataDir == "" {
		c.DataDir = DefaultDataDir()
	}
	if c.InstallDir == "" {
		c.InstallDir = DefaultInstallDir()
	}
	return c, c.validate()
}

func (c *Config) validate() error {
	host, port, err := net.SplitHostPort(c.Server)
	if err != nil || host == "" {
		return fmt.Errorf("server must be host:port, got %q", c.Server)
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("invalid server port %q", port)
	}
	pemData := []byte(c.RootCAPEM)
	// Registry and GPO values are single-line: accept the certificate also
	// as base64 DER (openrmm-admin pki root-b64).
	if len(pemData) > 0 && !strings.Contains(c.RootCAPEM, "-----BEGIN") {
		der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(c.RootCAPEM))
		if err != nil {
			return errors.New("root CA must be PEM or base64 DER")
		}
		pemData = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	if len(pemData) == 0 {
		if c.RootCAFile == "" {
			return errors.New("the pinned root CA is required (root_ca_file or root_ca_pem)")
		}
		pemData, err = os.ReadFile(c.RootCAFile)
		if err != nil {
			return fmt.Errorf("read root CA: %w", err)
		}
	}
	certs, err := pki.ParseCertsPEM(pemData)
	if err != nil {
		return fmt.Errorf("root CA: %w", err)
	}
	if len(certs) != 1 || !certs[0].IsCA {
		return errors.New("root CA must be exactly one CA certificate")
	}
	c.root = certs[0]
	c.keys = signing.NewKeyring()
	for _, s := range c.JobSigningKeys {
		pub, err := signing.ParsePublicKey(s)
		if err != nil {
			return fmt.Errorf("job signing key: %w", err)
		}
		// The signer signs both jobs and policies with the same key.
		if _, err := c.keys.Add(ed25519.PublicKey(pub), signing.DomainJob, signing.DomainPolicy); err != nil {
			return err
		}
	}
	c.moduleKeys = signing.NewKeyring()
	for _, s := range c.ModuleSigningKeys {
		pub, err := signing.ParsePublicKey(s)
		if err != nil {
			return fmt.Errorf("module signing key: %w", err)
		}
		if _, err := c.moduleKeys.Add(ed25519.PublicKey(pub), signing.DomainModuleManifest); err != nil {
			return err
		}
	}
	c.releaseKeys = signing.NewKeyring()
	for _, s := range c.ReleaseSigningKeys {
		pub, err := signing.ParsePublicKey(s)
		if err != nil {
			return fmt.Errorf("release signing key: %w", err)
		}
		if _, err := c.releaseKeys.Add(ed25519.PublicKey(pub), signing.DomainAgentRelease); err != nil {
			return err
		}
	}
	if !filepath.IsAbs(c.InstallDir) {
		return errors.New("install_dir must be an absolute path")
	}
	if c.MaxConcurrentJobs == 0 {
		c.MaxConcurrentJobs = 4
	}
	if c.MaxConcurrentJobs < 1 || c.MaxConcurrentJobs > 32 {
		return errors.New("max_concurrent_jobs must be between 1 and 32")
	}
	if !filepath.IsAbs(c.DataDir) {
		return errors.New("data_dir must be an absolute path")
	}
	return nil
}

// SplitList splits a single-line list of keys ("a,b" or "a;b").
func SplitList(s string) []string {
	var out []string
	for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' || r == '\n' }) {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ServerName returns the host part of Server, used for TLS verification.
func (c *Config) ServerName() string {
	h, _, _ := net.SplitHostPort(c.Server)
	return h
}

// RootCA returns the pinned root certificate.
func (c *Config) RootCA() *x509.Certificate { return c.root }

// JobKeyring returns the trusted job signing keys.
func (c *Config) JobKeyring() *signing.Keyring { return c.keys }

// ModuleKeyring returns the trusted module release keys.
func (c *Config) ModuleKeyring() *signing.Keyring { return c.moduleKeys }

// ReleaseKeyring returns the trusted agent release keys.
func (c *Config) ReleaseKeyring() *signing.Keyring { return c.releaseKeys }

// InteractiveShellAllowed reports the local policy for shell sessions.
func (c *Config) InteractiveShellAllowed() bool {
	return c.AllowInteractiveShell == nil || *c.AllowInteractiveShell
}

// AdHocScriptsAllowed reports the effective local policy.
func (c *Config) AdHocScriptsAllowed() bool {
	return c.AllowAdHocScripts == nil || *c.AllowAdHocScripts
}
