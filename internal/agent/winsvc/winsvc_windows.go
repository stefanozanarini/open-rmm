//go:build windows

// Package winsvc runs and installs the open-rmm Windows services.
package winsvc

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

// IsService reports whether the process was started by the SCM.
func IsService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}

type handler struct {
	run func(context.Context, *slog.Logger) error
	log *slog.Logger
}

func (h *handler) Execute(_ []string, req <-chan svc.ChangeRequest, st chan<- svc.Status) (bool, uint32) {
	st <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.run(ctx, h.log) }()
	st <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			cancel()
			if err != nil {
				h.log.Error("service stopped", "err", err)
				// A non-zero exit makes the SCM apply the recovery actions.
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

// Run runs fn as the service name, logging to the Windows event log.
func Run(name string, fn func(context.Context, *slog.Logger) error) error {
	return svc.Run(name, &handler{run: fn, log: slog.New(slog.NewTextHandler(eventLogWriter(name), nil))})
}

// Install registers a service with automatic start and recovery actions
// (restart after 5s, 30s, then every 2 minutes; counter reset after a day).
func Install(name, display, description string, args ...string) error {
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
	if s, err := m.OpenService(name); err == nil {
		s.Close()
		return fmt.Errorf("service %s already installed", name)
	}
	s, err := m.CreateService(name, exe, mgr.Config{
		DisplayName: display, Description: description,
		StartType: mgr.StartAutomatic, DelayedAutoStart: true, ServiceStartName: "LocalSystem",
	}, args...)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 2 * time.Minute},
	}, uint32((24 * time.Hour).Seconds())); err != nil {
		return err
	}
	if err := s.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		return err
	}
	_ = eventlog.InstallAsEventCreate(name, eventlog.Error|eventlog.Warning|eventlog.Info)
	return nil
}

// Uninstall removes a service.
func Uninstall(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return err
	}
	defer s.Close()
	_ = eventlog.Remove(name)
	return s.Delete()
}

const taskName = `\open-rmm\Controllo servizi`

// InstallHealthTask creates the scheduled task that, every 15 minutes and at
// startup, starts both services if they are stopped. It only calls sc.exe,
// whose path never changes when open-rmm is updated.
func InstallHealthTask() error {
	sc := filepath.Join(os.Getenv("SystemRoot"), "System32", "sc.exe")
	cmd := filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
	action := fmt.Sprintf(`"%s" /c "%s" start openrmm-watchdog ^& "%s" start openrmm-agent`, cmd, sc, sc)
	schtasks := filepath.Join(os.Getenv("SystemRoot"), "System32", "schtasks.exe")
	out, err := exec.Command(schtasks, "/Create", "/F", "/TN", taskName, "/RU", "SYSTEM", "/RL", "HIGHEST", // #nosec G204 -- fixed system binaries
		"/SC", "MINUTE", "/MO", "15", "/TR", action).CombinedOutput()
	if err != nil {
		return fmt.Errorf("schtasks: %v: %s", err, out)
	}
	return nil
}

// UninstallHealthTask removes the scheduled task.
func UninstallHealthTask() error {
	schtasks := filepath.Join(os.Getenv("SystemRoot"), "System32", "schtasks.exe")
	out, err := exec.Command(schtasks, "/Delete", "/F", "/TN", taskName).CombinedOutput() // #nosec G204 -- fixed system binary
	if err != nil {
		return fmt.Errorf("schtasks: %v: %s", err, out)
	}
	return nil
}

func eventLogWriter(name string) *elWriter {
	l, err := eventlog.Open(name)
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
