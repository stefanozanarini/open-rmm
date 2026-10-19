//go:build windows

package policies

import (
	"os"
	"strings"

	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/stefanozanarini/open-rmm/internal/agent/hostinfo"
)

// SystemProbe inspects the local system.
type SystemProbe struct{}

func (SystemProbe) ServiceExists(name string) bool {
	m, err := mgr.Connect()
	if err != nil {
		return false
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return false
	}
	s.Close()
	return true
}

// expandable lists the only variables a path may use.
var expandable = []string{"ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "ProgramData", "SystemRoot", "SystemDrive", "CommonProgramFiles"}

func expand(path string) string {
	for _, v := range expandable {
		path = strings.ReplaceAll(path, "%"+v+"%", os.Getenv(v))
	}
	return path
}

func (SystemProbe) FileExists(path string) bool {
	path = expand(path)
	if strings.Contains(path, "%") {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

func (SystemProbe) RegistryKeyExists(path string) bool {
	rest, ok := strings.CutPrefix(path, `HKLM\`)
	if !ok {
		rest, ok = strings.CutPrefix(path, `hklm\`)
	}
	if !ok {
		return false
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, rest, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return false
	}
	k.Close()
	return true
}

func (SystemProbe) OSFamily() string { return hostinfo.OSFamily() }
