// Package svcctl controls the agent's OS services (Windows Service Control
// Manager, systemd), including which executable each service runs: that is
// how versions are switched (A/B) and rolled back.
package svcctl

import "time"

const (
	Agent    = "openrmm-agent"
	Watchdog = "openrmm-watchdog"
)

// Manager controls services.
type Manager interface {
	Running(name string) (bool, error)
	Start(name string) error
	// Stop waits up to timeout for the service to stop.
	Stop(name string, timeout time.Duration) error
	// Binary returns the executable the service currently runs.
	Binary(name string) (string, error)
	// SetBinary makes the service run exe with args from its next start.
	SetBinary(name, exe string, args []string) error
}
