//go:build !windows

package hostinfo

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

func osVersion() string {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return ""
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		if v, ok := strings.CutPrefix(s.Text(), "PRETTY_NAME="); ok {
			return strings.Trim(v, `"'`)
		}
	}
	return ""
}

// OSFamily tells a Linux desktop from a server: a machine with a display
// manager or that boots to the graphical target is a client. A server
// installed with a desktop counts as a client.
func OSFamily() string {
	if _, err := os.Lstat("/etc/systemd/system/display-manager.service"); err == nil {
		return "client"
	}
	for _, p := range []string{"/etc/systemd/system/default.target", "/lib/systemd/system/default.target", "/usr/lib/systemd/system/default.target"} {
		if t, err := os.Readlink(p); err == nil {
			if filepath.Base(t) == "graphical.target" {
				return "client"
			}
			return "server"
		}
	}
	return "server"
}

func machineID() string {
	b, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
