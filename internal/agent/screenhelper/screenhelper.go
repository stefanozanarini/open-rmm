// Package screenhelper is the process the agent launches inside the
// logged-on user's desktop session (see internal/agent/usersession) to
// serve a remote-control session: it captures the screen and injects
// mouse/keyboard input, speaking internal/screensession on its
// stdin/stdout. It never talks to the console directly — the agent, in
// session 0, pumps the bytes to and from the gRPC stream unchanged.
package screenhelper

import "errors"

// ErrUnsupported is returned where screen capture/injection is not
// implemented (today: everywhere but Windows).
var ErrUnsupported = errors.New("remote control is not supported on this system")
