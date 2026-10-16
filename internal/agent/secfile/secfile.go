// Package secfile writes files readable only by the service account: SYSTEM
// and Administrators on Windows, the owner (root) on Unix.
package secfile

import (
	"fmt"
	"os"
	"path/filepath"
)

// EnsureDir creates dir if needed and restricts its access.
func EnsureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return restrictDir(dir)
}

// WriteFile atomically replaces path with data. The parent directory must
// have been prepared with EnsureDir.
func WriteFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".tmp-"+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if err := restrictFile(f); err != nil {
		return fmt.Errorf("restrict %s: %w", tmp, err)
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	return nil
}
