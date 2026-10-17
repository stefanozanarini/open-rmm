// Package health is the file through which the agent tells the watchdog it
// is alive, which version it runs and whether it reaches the console.
package health

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/agent/secfile"
)

const fileName = "health.json"

// Interval is how often the agent refreshes the file.
const Interval = 30 * time.Second

type Health struct {
	Version       string    `json:"version"`
	PID           int       `json:"pid"`
	Executable    string    `json:"executable"`
	Updated       time.Time `json:"updated"`
	Started       time.Time `json:"started"`
	Connected     bool      `json:"connected"`
	LastConnected time.Time `json:"last_connected,omitempty"`
}

func Write(dataDir string, h Health) error {
	raw, err := json.Marshal(h)
	if err != nil {
		return err
	}
	return secfile.WriteFile(filepath.Join(dataDir, fileName), raw)
}

func Read(dataDir string) (Health, error) {
	var h Health
	raw, err := os.ReadFile(filepath.Join(dataDir, fileName)) // #nosec G304 -- agent data dir
	if err != nil {
		return h, err
	}
	return h, json.Unmarshal(raw, &h)
}
