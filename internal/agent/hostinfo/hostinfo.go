// Package hostinfo collects the minimal host description sent on connect.
// The full hardware inventory is a module, not part of the core.
package hostinfo

import (
	"os"
	"runtime"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
)

// Collect returns the host description.
func Collect(agentVersion string) *openrmmv1.HostInfo {
	h, _ := os.Hostname()
	return &openrmmv1.HostInfo{
		Hostname:     h,
		Os:           runtime.GOOS,
		OsVersion:    osVersion(),
		Arch:         runtime.GOARCH,
		AgentVersion: agentVersion,
		MachineId:    machineID(),
		OsFamily:     OSFamily(),
	}
}
