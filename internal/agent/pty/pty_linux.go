//go:build linux

package pty

import (
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// Process is a program running on a pseudo-terminal.
type Process struct {
	master *os.File
	cmd    *exec.Cmd
	once   sync.Once
}

// Start runs argv on a new pseudo-terminal, in its own session.
func Start(argv, env []string, dir string, cols, rows uint16) (*Process, error) {
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	fd := int(master.Fd()) // #nosec G115 -- file descriptors fit in int
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		master.Close()
		return nil, err
	}
	n, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		master.Close()
		return nil, err
	}
	slave, err := os.OpenFile("/dev/pts/"+strconv.Itoa(n), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		master.Close()
		return nil, err
	}
	defer slave.Close()
	p := &Process{master: master}
	if err := p.Resize(cols, rows); err != nil {
		master.Close()
		return nil, err
	}
	cmd := exec.Command(argv[0], argv[1:]...) // #nosec G204 -- fixed shell chosen by the agent
	cmd.Env, cmd.Dir = env, dir
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		master.Close()
		return nil, err
	}
	p.cmd = cmd
	return p, nil
}

func (p *Process) Read(b []byte) (int, error) {
	n, err := p.master.Read(b)
	if err != nil && n == 0 {
		// EIO once the program has exited.
		return 0, err
	}
	return n, nil
}

func (p *Process) Write(b []byte) (int, error) { return p.master.Write(b) }

// Resize changes the terminal size.
func (p *Process) Resize(cols, rows uint16) error {
	cols, rows = clampSize(cols, rows)
	return unix.IoctlSetWinsize(int(p.master.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Col: cols, Row: rows}) // #nosec G115 -- file descriptors fit in int
}

// Wait waits for the program to exit.
func (p *Process) Wait() error { return p.cmd.Wait() }

// Close kills the process group and releases the terminal.
func (p *Process) Close() {
	p.once.Do(func() {
		if p.cmd != nil && p.cmd.Process != nil {
			_ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
		}
		_ = p.master.Close()
	})
}
