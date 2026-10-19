// Package pkgref validates the package references carried by signed jobs,
// on the console, in the signer and on the agent.
package pkgref

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"regexp"
	"strings"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
)

const (
	// MaxSize bounds one package.
	MaxSize = 4 << 30
	// MaxPerJob bounds the packages of one job.
	MaxPerJob = 5
)

// fileNameRe allows plain file names only: no paths, no leading dot.
var fileNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._()+,-]{0,150}\.[A-Za-z0-9]{1,8}$`)

// ValidFileName reports whether name is safe as a file name on every OS.
func ValidFileName(name string) bool {
	if !fileNameRe.MatchString(name) || strings.Contains(name, "..") || strings.HasSuffix(name, " ") {
		return false
	}
	base := strings.ToUpper(strings.SplitN(name, ".", 2)[0])
	switch base {
	case "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "LPT1", "LPT2", "LPT3":
		return false
	}
	return true
}

// Validate checks the package references of a job.
func Validate(refs []*openrmmv1.PackageRef) error {
	if len(refs) > MaxPerJob {
		return fmt.Errorf("at most %d packages per job", MaxPerJob)
	}
	names := map[string]bool{}
	for _, r := range refs {
		if len(r.GetSha256()) != sha256.Size {
			return errors.New("package hash must be SHA-256")
		}
		if !ValidFileName(r.GetFileName()) {
			return fmt.Errorf("invalid package file name %q", r.GetFileName())
		}
		if n := strings.ToLower(r.GetFileName()); names[n] {
			return errors.New("duplicate package file name")
		} else {
			names[n] = true
		}
		if r.GetSize() <= 0 || r.GetSize() > MaxSize {
			return errors.New("invalid package size")
		}
	}
	return nil
}
