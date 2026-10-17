//go:build windows

package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

const (
	installKey = `SOFTWARE\open-rmm`
	policyKey  = `SOFTWARE\Policies\open-rmm`
)

func programData() string {
	if p := os.Getenv("ProgramData"); p != "" {
		return p
	}
	return `C:\ProgramData`
}

// DefaultConfigPath is where the agent looks for its configuration.
func DefaultConfigPath() string { return filepath.Join(programData(), "open-rmm", "agent.json") }

// DefaultDataDir is where the agent keeps keys and state.
func DefaultDataDir() string { return filepath.Join(programData(), "open-rmm", "data") }

// overlayOS applies the MSI key, then the GPO policy key on top of it.
//
// Registry values (all optional):
//
//	Server            REG_SZ        agent.example.com:443
//	RootCA            REG_SZ        PEM of the root certificate
//	EnrollToken       REG_SZ        enrollment token
//	JobSigningKeys    REG_MULTI_SZ  ed25519:... (one per line)
//	ModuleSigningKeys REG_MULTI_SZ  ed25519:... (one per line)
//	AllowAdHocScripts REG_DWORD     0 or 1
//	MaxConcurrentJobs REG_DWORD     1-32
func overlayOS(c *Config) error {
	for _, path := range []string{installKey, policyKey} {
		if err := overlayKey(c, path); err != nil {
			return err
		}
	}
	return nil
}

func overlayKey(c *Config, path string) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer k.Close()
	str := func(name string, dst *string) {
		if v, _, err := k.GetStringValue(name); err == nil && strings.TrimSpace(v) != "" {
			*dst = strings.TrimSpace(v)
		}
	}
	str("Server", &c.Server)
	str("EnrollToken", &c.EnrollToken)
	if v, _, err := k.GetStringValue("RootCA"); err == nil && strings.TrimSpace(v) != "" {
		c.RootCAPEM = v
		c.RootCAFile = ""
	}
	if v, _, err := k.GetStringsValue("JobSigningKeys"); err == nil && len(v) > 0 {
		c.JobSigningKeys = v
	}
	if v, _, err := k.GetStringsValue("ModuleSigningKeys"); err == nil && len(v) > 0 {
		c.ModuleSigningKeys = v
	}
	if v, _, err := k.GetIntegerValue("MaxConcurrentJobs"); err == nil && v <= 32 {
		c.MaxConcurrentJobs = int(v)
	}
	if v, _, err := k.GetIntegerValue("AllowAdHocScripts"); err == nil {
		b := v != 0
		c.AllowAdHocScripts = &b
	}
	return nil
}
