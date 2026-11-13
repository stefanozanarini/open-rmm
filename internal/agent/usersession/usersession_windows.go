//go:build windows

package usersession

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/stefanozanarini/tempra-rmm/internal/agent/pty"
)

// Process is a program running inside the logged-on user's desktop
// session, with its stdin/stdout wired to plain pipes.
type Process struct {
	in, out *os.File
	process windows.Handle
	job     windows.Handle
	once    sync.Once
}

// Start runs argv inside the desktop session of the user logged on at the
// console (the active session's shell, "winsta0\default"), in a job
// object so the whole process tree is killed when the session ends.
func Start(argv, env []string, dir string) (*Process, error) {
	sessionID := windows.WTSGetActiveConsoleSessionId()
	if sessionID == 0xFFFFFFFF {
		return nil, ErrNoUser
	}
	var userToken windows.Token
	if err := windows.WTSQueryUserToken(sessionID, &userToken); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoUser, err)
	}
	defer userToken.Close()
	var token windows.Token
	if err := windows.DuplicateTokenEx(userToken, 0, nil, windows.SecurityImpersonation, windows.TokenPrimary, &token); err != nil {
		return nil, fmt.Errorf("duplicate user token: %w", err)
	}
	defer token.Close()

	// Both ends start inheritable; the ends this process keeps are cleared
	// right after, so only the child's ends are inherited.
	sa := &windows.SecurityAttributes{InheritHandle: 1}
	var inR, inW, outR, outW windows.Handle
	if err := windows.CreatePipe(&inR, &inW, sa, 0); err != nil {
		return nil, err
	}
	if err := windows.CreatePipe(&outR, &outW, sa, 0); err != nil {
		windows.CloseHandle(inR)
		windows.CloseHandle(inW)
		return nil, err
	}
	if err := windows.SetHandleInformation(inW, windows.HANDLE_FLAG_INHERIT, 0); err != nil {
		closeAll(inR, inW, outR, outW)
		return nil, err
	}
	if err := windows.SetHandleInformation(outR, windows.HANDLE_FLAG_INHERIT, 0); err != nil {
		closeAll(inR, inW, outR, outW)
		return nil, err
	}

	p := &Process{in: os.NewFile(uintptr(inW), "usersession-in"), out: os.NewFile(uintptr(outR), "usersession-out")}
	if err := p.start(token, argv, env, dir, inR, outW); err != nil {
		windows.CloseHandle(inR)
		windows.CloseHandle(outW)
		p.in.Close()
		p.out.Close()
		return nil, err
	}
	windows.CloseHandle(inR)
	windows.CloseHandle(outW)
	return p, nil
}

func closeAll(h ...windows.Handle) {
	for _, x := range h {
		windows.CloseHandle(x)
	}
}

func (p *Process) start(token windows.Token, argv, env []string, dir string, stdin, stdout windows.Handle) error {
	desktop, err := windows.UTF16PtrFromString(`winsta0\default`)
	if err != nil {
		return err
	}
	si := &windows.StartupInfo{
		Desktop:   desktop,
		Flags:     windows.STARTF_USESTDHANDLES,
		StdInput:  stdin,
		StdOutput: stdout,
		StdErr:    stdout,
	}
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
	envp, err := pty.EnvBlock(env)
	if err != nil {
		return err
	}
	if p.job, err = newJob(); err != nil {
		return err
	}
	flags := uint32(windows.CREATE_UNICODE_ENVIRONMENT | windows.CREATE_NO_WINDOW | windows.CREATE_SUSPENDED)
	var pi windows.ProcessInformation
	if err := windows.CreateProcessAsUser(token, nil, cmdline, nil, nil, true, flags, &envp[0], dirp, si, &pi); err != nil {
		windows.CloseHandle(p.job)
		p.job = 0
		return fmt.Errorf("start process in user session: %w", err)
	}
	p.process = pi.Process
	if err := windows.AssignProcessToJobObject(p.job, pi.Process); err != nil {
		_ = windows.TerminateProcess(pi.Process, 1)
		windows.CloseHandle(pi.Thread)
		return fmt.Errorf("assign process to job object: %w", err)
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

// Wait waits for the process to exit.
func (p *Process) Wait() error {
	_, err := windows.WaitForSingleObject(p.process, windows.INFINITE)
	return err
}

// Close kills the process tree and releases its handles.
func (p *Process) Close() {
	p.once.Do(func() {
		if p.job != 0 {
			_ = windows.TerminateJobObject(p.job, 1)
			windows.CloseHandle(p.job)
		}
		if p.process != 0 {
			windows.CloseHandle(p.process)
		}
		p.in.Close()
		p.out.Close()
	})
}
