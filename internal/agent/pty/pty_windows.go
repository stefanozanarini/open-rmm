//go:build windows

package pty

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Process is a program running on a ConPTY, inside a Job Object.
type Process struct {
	console windows.Handle
	in, out *os.File
	process windows.Handle
	job     windows.Handle
	once    sync.Once
}

// Start runs argv on a new pseudo console.
func Start(argv, env []string, dir string, cols, rows uint16) (*Process, error) {
	cols, rows = clampSize(cols, rows)
	var inR, inW, outR, outW windows.Handle
	if err := windows.CreatePipe(&inR, &inW, nil, 0); err != nil {
		return nil, err
	}
	if err := windows.CreatePipe(&outR, &outW, nil, 0); err != nil {
		windows.CloseHandle(inR)
		windows.CloseHandle(inW)
		return nil, err
	}
	p := &Process{in: os.NewFile(uintptr(inW), "pty-in"), out: os.NewFile(uintptr(outR), "pty-out")}
	size := windows.Coord{X: int16(cols), Y: int16(rows)} // #nosec G115 -- clamped to 1000
	err := windows.CreatePseudoConsole(size, inR, outW, 0, &p.console)
	// The console keeps its own copies of its ends of the pipes.
	windows.CloseHandle(inR)
	windows.CloseHandle(outW)
	if err != nil {
		p.in.Close()
		p.out.Close()
		return nil, fmt.Errorf("create pseudo console: %w", err)
	}
	if err := p.start(argv, env, dir); err != nil {
		p.Close()
		return nil, err
	}
	return p, nil
}

func (p *Process) start(argv, env []string, dir string) error {
	attrs, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return err
	}
	defer attrs.Delete()
	// The attribute value is the HPCON itself, not a pointer to it.
	hpc := *(*unsafe.Pointer)(unsafe.Pointer(&p.console))                                                            // #nosec G103 -- Win32 API call
	if err := attrs.Update(windows.PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, hpc, unsafe.Sizeof(p.console)); err != nil { // #nosec G103 -- Win32 API call
		return err
	}
	si := &windows.StartupInfoEx{ProcThreadAttributeList: attrs.List()}
	si.Cb = uint32(unsafe.Sizeof(*si)) // #nosec G103 -- Win32 API call
	quoted := make([]string, len(argv))
	for i, a := range argv {
		quoted[i] = syscall.EscapeArg(a)
	}
	cmdline, err := windows.UTF16PtrFromString(strings.Join(quoted, " "))
	if err != nil {
		return err
	}
	var dirp *uint16
	if dir != "" {
		if dirp, err = windows.UTF16PtrFromString(dir); err != nil {
			return err
		}
	}
	envp, err := envBlock(env)
	if err != nil {
		return err
	}
	if p.job, err = newJob(); err != nil {
		return err
	}
	var pi windows.ProcessInformation
	flags := uint32(windows.EXTENDED_STARTUPINFO_PRESENT | windows.CREATE_UNICODE_ENVIRONMENT | windows.CREATE_SUSPENDED)
	if err := windows.CreateProcess(nil, cmdline, nil, nil, false, flags, &envp[0], dirp, &si.StartupInfo, &pi); err != nil {
		return fmt.Errorf("start shell: %w", err)
	}
	p.process = pi.Process
	// In the job before it runs a single instruction: nothing escapes it.
	if err := windows.AssignProcessToJobObject(p.job, pi.Process); err != nil {
		_ = windows.TerminateProcess(pi.Process, 1)
		windows.CloseHandle(pi.Thread)
		return fmt.Errorf("assign shell to job object: %w", err)
	}
	_, err = windows.ResumeThread(pi.Thread)
	windows.CloseHandle(pi.Thread)
	return err
}

func newJob() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE},
	}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil { // #nosec G103 -- Win32 API call
		windows.CloseHandle(job)
		return 0, err
	}
	return job, nil
}

func (p *Process) Read(b []byte) (int, error)  { return p.out.Read(b) }
func (p *Process) Write(b []byte) (int, error) { return p.in.Write(b) }

// Resize changes the console size.
func (p *Process) Resize(cols, rows uint16) error {
	cols, rows = clampSize(cols, rows)
	return windows.ResizePseudoConsole(p.console, windows.Coord{X: int16(cols), Y: int16(rows)}) // #nosec G115 -- clamped to 1000
}

// Wait waits for the shell to exit.
func (p *Process) Wait() error {
	_, err := windows.WaitForSingleObject(p.process, windows.INFINITE)
	return err
}

// Close kills the process tree and releases the console.
func (p *Process) Close() {
	p.once.Do(func() {
		if p.job != 0 {
			_ = windows.TerminateJobObject(p.job, 1)
			windows.CloseHandle(p.job)
		}
		if p.console != 0 {
			windows.ClosePseudoConsole(p.console)
		}
		if p.process != 0 {
			windows.CloseHandle(p.process)
		}
		p.in.Close()
		p.out.Close()
	})
}
