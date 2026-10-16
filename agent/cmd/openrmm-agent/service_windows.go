//go:build windows

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "openrmm-agent"

func isService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}

type handler struct {
	cfgPath string
	log     *slog.Logger
}

func (h *handler) Execute(_ []string, req <-chan svc.ChangeRequest, st chan<- svc.Status) (bool, uint32) {
	st <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runAgent(ctx, h.cfgPath, h.log) }()
	st <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			cancel()
			if err != nil {
				h.log.Error("agent stopped", "err", err)
				// A non-zero exit makes the Service Control Manager apply
				// the recovery actions (restart).
				return true, 1
			}
			return false, 0
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				st <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				st <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case <-done:
				case <-time.After(20 * time.Second):
				}
				return false, 0
			}
		}
	}
}

func runService(cfgPath string) error {
	log := slog.New(slog.NewTextHandler(eventLogWriter(), nil))
	return svc.Run(serviceName, &handler{cfgPath: cfgPath, log: log})
}

// installService registers the service with automatic start and recovery
// actions. In production the MSI does this; the command is for development.
func installService(cfgPath string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, err = filepath.Abs(exe)
	if err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	if s, err := m.OpenService(serviceName); err == nil {
		s.Close()
		return fmt.Errorf("service %s already installed", serviceName)
	}
	s, err := m.CreateService(serviceName, exe, mgr.Config{
		DisplayName:      "open-rmm agent",
		Description:      "open-rmm endpoint management agent",
		StartType:        mgr.StartAutomatic,
		DelayedAutoStart: true,
		ServiceStartName: "LocalSystem",
	}, "run", "-config", cfgPath)
	if err != nil {
		return err
	}
	defer s.Close()
	// Restart after 5s, 30s, then every 2 minutes; reset the failure count
	// after a day without failures.
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 2 * time.Minute},
	}, uint32((24 * time.Hour).Seconds())); err != nil {
		return err
	}
	// Apply recovery also when the service stops with a non-zero exit code,
	// not only on crashes.
	if err := s.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		return err
	}
	_ = eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info)
	return nil
}

func uninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer s.Close()
	_ = eventlog.Remove(serviceName)
	return s.Delete()
}

// eventLogWriter sends log lines to the Windows event log.
func eventLogWriter() *elWriter {
	l, err := eventlog.Open(serviceName)
	if err != nil {
		return &elWriter{}
	}
	return &elWriter{l: l}
}

type elWriter struct{ l *eventlog.Log }

func (w *elWriter) Write(p []byte) (int, error) {
	if w.l == nil {
		return len(p), nil
	}
	return len(p), w.l.Info(1, string(p))
}
