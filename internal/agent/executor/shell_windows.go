//go:build windows

package executor

import (
	"os"
	"path/filepath"
)

// shellCommand is Windows PowerShell, by absolute path, running the
// module's startup script and staying interactive.
func shellCommand(startup, workDir string) ([]string, []string) {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	exe := filepath.Join(root, `System32\WindowsPowerShell\v1.0\powershell.exe`)
	return []string{exe, "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-NoExit", "-File", startup},
		append(os.Environ(), "TEMP="+workDir, "TMP="+workDir)
}
