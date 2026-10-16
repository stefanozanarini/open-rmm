//go:build !windows

package main

import "errors"

// On Linux the agent runs under systemd (packaging/linux), which handles
// restarts; there is no separate service mode.
func isService() bool { return false }

func runService(string) error { return errors.New("service mode is Windows only") }

func installService(string) error {
	return errors.New("use the systemd unit in packaging/linux")
}

func uninstallService() error {
	return errors.New("use systemctl disable --now openrmm-agent")
}
