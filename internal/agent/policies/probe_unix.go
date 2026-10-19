//go:build !windows

package policies

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/stefanozanarini/open-rmm/internal/agent/hostinfo"
)

// SystemProbe inspects the local system.
type SystemProbe struct{}

var unitDirs = []string{"/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"}

func (SystemProbe) ServiceExists(name string) bool {
	if !strings.HasSuffix(name, ".service") {
		name += ".service"
	}
	for _, d := range unitDirs {
		if _, err := os.Stat(filepath.Join(d, name)); err == nil {
			return true
		}
	}
	return false
}

func (SystemProbe) FileExists(path string) bool {
	if !filepath.IsAbs(path) {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

func (SystemProbe) RegistryKeyExists(string) bool { return false }

func (SystemProbe) OSFamily() string { return hostinfo.OSFamily() }
