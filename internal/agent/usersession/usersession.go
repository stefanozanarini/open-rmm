// Package usersession runs a program inside the desktop session of the
// user logged on at the console, from an agent that itself runs as
// LocalSystem in session 0 (no desktop). This is the only way for the
// agent to reach a real desktop: GDI screen capture and SendInput both
// require an interactive window station, which session 0 does not have.
//
// The child's stdin/stdout are plain anonymous pipes, not a pseudo
// console: the caller speaks its own binary framing on them (screen
// frames out, input events in), and a ConPTY would reinterpret those
// bytes as terminal escape sequences.
package usersession

import "errors"

// ErrNoUser is returned when no user is logged on the active console
// session, so there is no desktop to run in.
var ErrNoUser = errors.New("no interactive user is logged on")
