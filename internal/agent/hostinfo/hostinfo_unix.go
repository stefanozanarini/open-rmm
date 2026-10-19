//go:build !windows

package hostinfo

import (
	"bufio"
	"os"
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

// OSFamily is "unknown" on Linux: there is no reliable client/server marker.
func OSFamily() string { return "unknown" }

func machineID() string {
	b, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
