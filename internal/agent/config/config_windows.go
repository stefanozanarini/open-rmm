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

// DefaultInstallDir holds the installed versions.
func DefaultInstallDir() string {
	if p := os.Getenv("ProgramFiles"); p != "" {
		return filepath.Join(p, "open-rmm")
	}
	return `C:\Program Files\open-rmm`
}

// ForgetEnrollToken deletes the token written by the MSI once the agent is
// enrolled, so it does not linger in the registry. A token set by GPO
// (Policies key) is managed by the domain and left alone.
func ForgetEnrollToken() error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, installKey, registry.SET_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer k.Close()
	err = k.DeleteValue("EnrollToken")
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	return err
}

// overlayOS applies the MSI key, then the GPO policy key on top of it.
//
// Registry values (all optional):
//
//	Server            REG_SZ        agent.example.com:443
//	RootCA            REG_SZ        PEM of the root certificate
//	EnrollToken       REG_SZ        enrollment token
//	RootCA can also be base64 DER (single line)
//	JobSigningKeys    REG_MULTI_SZ, or REG_SZ separated by , or ;
//	ModuleSigningKeys  idem
//	ReleaseSigningKeys idem
//	AllowAdHocScripts REG_DWORD 0/1, or REG_SZ "0"/"1" (empty: not set)
//	AllowInteractiveShell REG_DWORD 0/1 (default 1; the MSI writes 1)
//	MaxConcurrentJobs REG_DWORD     1-32
func overlayOS(c *Config) error {
	for _, path := range []string{installKey, policyKey} {
		if err := overlayKey(c, path); err != nil {
			return err
		}
	}
	return nil
}

// keys reads a list of public keys, as REG_MULTI_SZ or as a REG_SZ with
// comma or semicolon separators (what MSI properties and ADMX text produce).
func keys(k registry.Key, name string, dst *[]string) {
	if v, _, err := k.GetStringsValue(name); err == nil && len(v) > 0 {
		*dst = v
		return
	}
	if v, _, err := k.GetStringValue(name); err == nil {
		if l := SplitList(v); len(l) > 0 {
			*dst = l
		}
	}
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
	keys(k, "JobSigningKeys", &c.JobSigningKeys)
	keys(k, "ModuleSigningKeys", &c.ModuleSigningKeys)
	keys(k, "ReleaseSigningKeys", &c.ReleaseSigningKeys)
	if v, _, err := k.GetIntegerValue("MaxConcurrentJobs"); err == nil && v <= 32 {
		c.MaxConcurrentJobs = int(v)
	}
	if v, _, err := k.GetIntegerValue("AllowInteractiveShell"); err == nil {
		b := v != 0
		c.AllowInteractiveShell = &b
	}
	// DWORD (ADMX, manual) or string "0"/"1" (MSI); empty means "not set".
	if v, _, err := k.GetIntegerValue("AllowAdHocScripts"); err == nil {
		b := v != 0
		c.AllowAdHocScripts = &b
	} else if v, _, err := k.GetStringValue("AllowAdHocScripts"); err == nil {
		switch strings.TrimSpace(v) {
		case "0":
			b := false
			c.AllowAdHocScripts = &b
		case "1":
			b := true
			c.AllowAdHocScripts = &b
		}
	}
	return nil
}
