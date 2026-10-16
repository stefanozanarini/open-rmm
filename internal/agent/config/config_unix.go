//go:build !windows

package config

// DefaultConfigPath is where the agent looks for its configuration.
func DefaultConfigPath() string { return "/etc/open-rmm/agent.json" }

// DefaultDataDir is where the agent keeps keys and state.
func DefaultDataDir() string { return "/var/lib/open-rmm" }

func overlayOS(*Config) error { return nil }
