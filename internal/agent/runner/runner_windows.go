//go:build windows

package runner

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/stefanozanarini/open-rmm/internal/modules"
)

const createNoWindow = 0x08000000

func systemRoot() string {
	if v := os.Getenv("SystemRoot"); v != "" {
		return v
	}
	return `C:\Windows`
}

func command(spec Spec) (*exec.Cmd, error) {
	var cmd *exec.Cmd
	switch spec.Type {
	case modules.TypeBinary:
		cmd = exec.Command(spec.Path) // #nosec G204 -- verified module entrypoint
	case modules.TypePowerShell:
		// Absolute path: never resolve powershell.exe through PATH.
		exe := filepath.Join(systemRoot(), `System32\WindowsPowerShell\v1.0\powershell.exe`)
		cmd = exec.Command(exe, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", spec.Path) // #nosec G204 -- verified module entrypoint
	default:
		return nil, fmt.Errorf("entrypoint type %q not supported on Windows", spec.Type)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow, HideWindow: true}
	return cmd, nil
}

func baseEnvironment(workDir string) []string {
	root := systemRoot()
	env := passthrough("SystemDrive", "ProgramData", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432",
		"CommonProgramFiles", "CommonProgramFiles(x86)", "CommonProgramW6432", "ALLUSERSPROFILE",
		"COMPUTERNAME", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE", "OS", "PATHEXT", "USERDOMAIN")
	return append(env,
		"SystemRoot="+root,
		"windir="+root,
		"PATH="+root+`\System32;`+root+`;`+root+`\System32\Wbem;`+root+`\System32\WindowsPowerShell\v1.0\`,
		"TEMP="+workDir,
		"TMP="+workDir,
		"USERPROFILE="+workDir,
	)
}

// processTree confines the module and its children to a Job Object that is
// terminated as a whole.
type processTree struct{ job windows.Handle }

func startTree(cmd *exec.Cmd) (*processTree, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, err
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		},
	}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil { // #nosec G103 -- Win32 API call
		windows.CloseHandle(job)
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		windows.CloseHandle(job)
		return nil, err
	}
	h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid)) // #nosec G115 -- PIDs fit in uint32
	if err == nil {
		err = windows.AssignProcessToJobObject(job, h)
		windows.CloseHandle(h)
	}
	if err != nil {
		_ = cmd.Process.Kill()
		windows.CloseHandle(job)
		return nil, fmt.Errorf("assign module to job object: %w", err)
	}
	return &processTree{job: job}, nil
}

func (t *processTree) kill() { _ = windows.TerminateJobObject(t.job, 1) }

// close kills anything still in the job (KILL_ON_JOB_CLOSE).
func (t *processTree) close() { windows.CloseHandle(t.job) }
