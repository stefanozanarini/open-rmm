// Package pty runs a program on a pseudo-terminal, for interactive shell
// sessions: a Unix PTY on Linux, a ConPTY on Windows (10 1809, Server 2019
// or later). The whole process tree is killed when the session ends.
package pty

import "errors"

// ErrUnsupported is returned where no pseudo-terminal is available.
var ErrUnsupported = errors.New("pseudo-terminals are not supported on this system")

// Size bounds a terminal.
const maxSize = 1000

func clampSize(cols, rows uint16) (uint16, uint16) {
	if cols == 0 {
		cols = 120
	}
	if rows == 0 {
		rows = 30
	}
	return min(cols, maxSize), min(rows, maxSize)
}
