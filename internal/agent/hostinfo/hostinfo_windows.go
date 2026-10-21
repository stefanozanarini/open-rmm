//go:build windows

package hostinfo

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"

	"github.com/stefanozanarini/open-rmm/internal/winver"
)

func osVersion() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	name, _, _ := k.GetStringValue("ProductName")
	display, _, _ := k.GetStringValue("DisplayVersion")
	build, _, _ := k.GetStringValue("CurrentBuild")
	ubr, _, _ := k.GetIntegerValue("UBR")
	return winver.Fix(fmt.Sprintf("%s %s (build %s.%d)", name, display, build, ubr))
}

// OSFamily returns "client" or "server" from the installation type
// ("Client", "Server", "Server Core", "Nano Server").
func OSFamily() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return "unknown"
	}
	defer k.Close()
	t, _, err := k.GetStringValue("InstallationType")
	switch {
	case err != nil:
		return "unknown"
	case strings.EqualFold(t, "Client"):
		return "client"
	case strings.Contains(strings.ToLower(t), "server"):
		return "server"
	}
	return "unknown"
}

func machineID() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, _ := k.GetStringValue("MachineGuid")
	return v
}
