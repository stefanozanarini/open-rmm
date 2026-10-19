//go:build !windows

package executor

import (
	"os"
)

// shellCommand is bash with the module's startup script as rc file, or sh
// reading it through ENV.
func shellCommand(startup, workDir string) ([]string, []string) {
	env := []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=" + workDir,
		"TERM=xterm-256color", "LANG=C.UTF-8", "TMPDIR=" + workDir}
	if _, err := os.Stat("/bin/bash"); err == nil {
		return []string{"/bin/bash", "--noprofile", "--rcfile", startup, "-i"}, env
	}
	return []string{"/bin/sh", "-i"}, append(env, "ENV="+startup)
}
