//go:build !windows

package secfile

import "os"

func restrictDir(dir string) error { return os.Chmod(dir, 0o700) }

func restrictFile(f *os.File) error { return f.Chmod(0o600) }
