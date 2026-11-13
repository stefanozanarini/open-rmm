//go:build !windows

package usersession

import "errors"

// ErrUnsupported is returned where running in the logged-on user's
// session is not available (today: everywhere but Windows).
var ErrUnsupported = errors.New("running in the user's session is not supported on this system")

// Process is unused on this platform.
type Process struct{}

// Start always fails: Linux/macOS agents do not yet support running a
// helper in the user's graphical session.
func Start(argv, env []string, dir string) (*Process, error) { return nil, ErrUnsupported }

func (p *Process) Read(b []byte) (int, error)  { return 0, ErrUnsupported }
func (p *Process) Write(b []byte) (int, error) { return 0, ErrUnsupported }
func (p *Process) Wait() error                 { return ErrUnsupported }
func (p *Process) Close()                      {}
