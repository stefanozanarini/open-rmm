//go:build !windows

package runner

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/stefanozanarini/open-rmm/internal/modules"
)

// pwshCandidates are tried for PowerShell modules on Linux (PowerShell 7).
var pwshCandidates = []string{"/usr/bin/pwsh", "/opt/microsoft/powershell/7/pwsh", "/usr/local/bin/pwsh"}

func command(spec Spec) (*exec.Cmd, error) {
	var cmd *exec.Cmd
	switch spec.Type {
	case modules.TypeBinary:
		cmd = exec.Command(spec.Path) // #nosec G204 -- verified module entrypoint
	case modules.TypeShell:
		cmd = exec.Command("/bin/sh", spec.Path) // #nosec G204 -- verified module entrypoint
	case modules.TypePowerShell:
		exe := ""
		for _, c := range pwshCandidates {
			if st, err := os.Stat(c); err == nil && st.Mode().IsRegular() {
				exe = c
				break
			}
		}
		if exe == "" {
			return nil, errors.New("PowerShell (pwsh) is not installed")
		}
		cmd = exec.Command(exe, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", spec.Path) // #nosec G204 -- verified module entrypoint
	default:
		return nil, fmt.Errorf("entrypoint type %q not supported on this platform", spec.Type)
	}
	// A new process group lets us kill the module and all its children.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return cmd, nil
}

func baseEnvironment(workDir string) []string {
	return append(passthrough("LANG", "TZ"),
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME="+workDir,
		"TMPDIR="+workDir,
	)
}

type processTree struct{ pid int }

func startTree(cmd *exec.Cmd) (*processTree, error) {
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &processTree{pid: cmd.Process.Pid}, nil
}

func (t *processTree) kill() { _ = syscall.Kill(-t.pid, syscall.SIGKILL) }

func (t *processTree) close() {}
