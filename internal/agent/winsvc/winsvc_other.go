//go:build !windows

// Package winsvc runs and installs the open-rmm Windows services. On other
// systems the services are managed by systemd (packaging/linux).
package winsvc

import (
	"context"
	"errors"
	"log/slog"
)

var errNotWindows = errors.New("only on Windows: on Linux use the systemd units in packaging/linux")

func IsService() bool { return false }

func Run(string, func(context.Context, *slog.Logger) error) error { return errNotWindows }

func Install(string, string, string, ...string) error { return errNotWindows }

func Ensure(string) error { return nil }

func Harden() error { return nil }

func Uninstall(string) error { return errNotWindows }

func InstallHealthTask() error { return errNotWindows }

func UninstallHealthTask() error { return errNotWindows }
