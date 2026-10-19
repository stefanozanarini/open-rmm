//go:build !linux && !windows

package pty

// Process is not available on this system.
type Process struct{}

// Start reports that pseudo-terminals are not supported.
func Start(argv, env []string, dir string, cols, rows uint16) (*Process, error) {
	return nil, ErrUnsupported
}

func (p *Process) Read([]byte) (int, error)    { return 0, ErrUnsupported }
func (p *Process) Write([]byte) (int, error)   { return 0, ErrUnsupported }
func (p *Process) Resize(uint16, uint16) error { return ErrUnsupported }
func (p *Process) Wait() error                 { return ErrUnsupported }
func (p *Process) Close()                      {}
