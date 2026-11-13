//go:build !windows

package screenhelper

import "io"

// Run always fails: Linux/macOS agents do not yet support remote control.
func Run(stdin io.Reader, stdout io.Writer) error { return ErrUnsupported }
