// Package updater installs signed agent releases side by side
// (InstallDir/versions/x.y.z) and hands them to the watchdog, which switches
// the service to the new version and rolls back if it does not come up.
package updater

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/agent/secfile"
)

const (
	pendingFile = "update-pending.json"
	resultFile  = "update-result.json"
	failedFile  = "update-failed.json"
)

// Pending is a staged release waiting for the watchdog.
type Pending struct {
	Version        string    `json:"version"`
	AgentExe       string    `json:"agent_exe"`
	AgentSHA256    string    `json:"agent_sha256"`
	WatchdogExe    string    `json:"watchdog_exe"`
	WatchdogSHA256 string    `json:"watchdog_sha256"`
	StagedAt       time.Time `json:"staged_at"`
}

// Result is written by the watchdog after applying a release.
type Result struct {
	Version string    `json:"version"`
	Applied bool      `json:"applied"`
	Error   string    `json:"error,omitempty"`
	At      time.Time `json:"at"`
}

func writeJSON(path string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return secfile.WriteFile(path, raw)
}

func readJSON(path string, v any) error {
	raw, err := os.ReadFile(path) // #nosec G304 -- agent data dir
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

func ReadPending(dataDir string) (*Pending, error) {
	var p Pending
	if err := readJSON(filepath.Join(dataDir, pendingFile), &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func WritePending(dataDir string, p Pending) error {
	return writeJSON(filepath.Join(dataDir, pendingFile), p)
}

func RemovePending(dataDir string) error {
	err := os.Remove(filepath.Join(dataDir, pendingFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func WriteResult(dataDir string, r Result) error {
	return writeJSON(filepath.Join(dataDir, resultFile), r)
}

// TakeResult returns and removes the last result, if any.
func TakeResult(dataDir string) (*Result, error) {
	var r Result
	p := filepath.Join(dataDir, resultFile)
	if err := readJSON(p, &r); err != nil {
		return nil, err
	}
	return &r, os.Remove(p)
}

// failed lists versions that were rolled back: they are not retried.
type failed struct {
	Versions map[string]string `json:"versions"` // version -> reason
}

func MarkFailed(dataDir, version, reason string) error {
	f := failed{Versions: map[string]string{}}
	_ = readJSON(filepath.Join(dataDir, failedFile), &f)
	if f.Versions == nil {
		f.Versions = map[string]string{}
	}
	f.Versions[version] = reason
	return writeJSON(filepath.Join(dataDir, failedFile), f)
}

func HasFailed(dataDir, version string) bool {
	var f failed
	if readJSON(filepath.Join(dataDir, failedFile), &f) != nil {
		return false
	}
	_, ok := f.Versions[version]
	return ok
}
