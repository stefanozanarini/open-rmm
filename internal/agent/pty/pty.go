// Package pty runs a program on a pseudo-terminal, for interactive shell
// sessions: a Unix PTY on Linux, a ConPTY on Windows (10 1809, Server 2019
// or later). The whole process tree is killed when the session ends.
package pty

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"
)

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

// envBlock builds a Windows environment block: UTF-16 "NAME=value" strings,
// each ending with a NUL, then a final NUL. (UTF16FromString cannot be used
// on the whole block: it refuses strings containing NUL.)
func envBlock(env []string) ([]uint16, error) {
	var out []uint16
	for _, e := range env {
		if strings.ContainsRune(e, 0) || !strings.Contains(e, "=") {
			return nil, fmt.Errorf("invalid environment entry %q", e)
		}
		out = append(out, utf16.Encode([]rune(e))...)
		out = append(out, 0)
	}
	if len(out) == 0 {
		out = append(out, 0) // an empty block still ends with two NULs
	}
	return append(out, 0), nil
}
