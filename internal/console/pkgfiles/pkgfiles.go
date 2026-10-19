// Package pkgfiles stores package files on disk, named by their SHA-256.
// The web console writes them; the core serves them to agents.
package pkgfiles

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
)

var shaRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ErrTooLarge is returned when a file exceeds the size limit.
var ErrTooLarge = errors.New("package too large")

// Dir is a directory of package files.
type Dir struct{ Path string }

// Save copies r into the store (at most max bytes) and returns its SHA-256
// (hex) and size. Saving a file that exists is a no-op.
func (d Dir) Save(r io.Reader, max int64) (string, int64, error) {
	if err := os.MkdirAll(d.Path, 0o750); err != nil {
		return "", 0, err
	}
	tmp, err := os.CreateTemp(d.Path, ".upload-*")
	if err != nil {
		return "", 0, err
	}
	defer os.Remove(tmp.Name())
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(r, max+1))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", 0, err
	}
	if n > max {
		return "", 0, ErrTooLarge
	}
	if n == 0 {
		return "", 0, errors.New("empty file")
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if err := os.Chmod(tmp.Name(), 0o400); err != nil {
		return "", 0, err
	}
	if err := os.Rename(tmp.Name(), filepath.Join(d.Path, sum)); err != nil {
		return "", 0, err
	}
	return sum, n, nil
}

// Open opens a stored file.
func (d Dir) Open(sha string) (*os.File, error) {
	if !shaRe.MatchString(sha) {
		return nil, fmt.Errorf("invalid package hash %q", sha)
	}
	return os.Open(filepath.Join(d.Path, sha)) // #nosec G304 -- validated hex name in the configured directory
}

// Remove deletes a stored file.
func (d Dir) Remove(sha string) error {
	if !shaRe.MatchString(sha) {
		return fmt.Errorf("invalid package hash %q", sha)
	}
	return os.Remove(filepath.Join(d.Path, sha))
}
