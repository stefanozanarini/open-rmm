//go:build windows

package svcctl

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// SCM is the Windows implementation.
type SCM struct{}

// New returns the platform Manager.
func New() Manager { return SCM{} }

func open(name string) (*mgr.Mgr, *mgr.Service, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, nil, err
	}
	s, err := m.OpenService(name)
	if err != nil {
		m.Disconnect()
		return nil, nil, err
	}
	return m, s, nil
}

func (SCM) Running(name string) (bool, error) {
	m, s, err := open(name)
	if err != nil {
		return false, err
	}
	defer m.Disconnect()
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		return false, err
	}
	return st.State == svc.Running || st.State == svc.StartPending, nil
}

func (SCM) Start(name string) error {
	m, s, err := open(name)
	if err != nil {
		return err
	}
	defer m.Disconnect()
	defer s.Close()
	err = s.Start()
	if errors.Is(err, syscall.Errno(1056)) { // ERROR_SERVICE_ALREADY_RUNNING
		return nil
	}
	return err
}

func (SCM) Stop(name string, timeout time.Duration) error {
	m, s, err := open(name)
	if err != nil {
		return err
	}
	defer m.Disconnect()
	defer s.Close()
	st, err := s.Control(svc.Stop)
	if err != nil && !errors.Is(err, syscall.Errno(1062)) { // ERROR_SERVICE_NOT_ACTIVE
		return err
	}
	deadline := time.Now().Add(timeout)
	for st.State != svc.Stopped {
		if time.Now().After(deadline) {
			return fmt.Errorf("%s did not stop within %s", name, timeout)
		}
		time.Sleep(500 * time.Millisecond)
		if st, err = s.Query(); err != nil {
			return err
		}
	}
	return nil
}

func (SCM) Binary(name string) (string, error) {
	m, s, err := open(name)
	if err != nil {
		return "", err
	}
	defer m.Disconnect()
	defer s.Close()
	cfg, err := s.Config()
	if err != nil {
		return "", err
	}
	return firstArg(cfg.BinaryPathName), nil
}

// firstArg extracts the executable from a service command line.
func firstArg(cmdline string) string {
	cmdline = strings.TrimSpace(cmdline)
	if strings.HasPrefix(cmdline, `"`) {
		if end := strings.Index(cmdline[1:], `"`); end >= 0 {
			return cmdline[1 : end+1]
		}
	}
	exe, _, _ := strings.Cut(cmdline, " ")
	return exe
}

func quote(s string) string {
	if strings.ContainsAny(s, " \t\"") {
		return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
	}
	return s
}

func (SCM) SetBinary(name, exe string, args []string) error {
	m, s, err := open(name)
	if err != nil {
		return err
	}
	defer m.Disconnect()
	defer s.Close()
	cfg, err := s.Config()
	if err != nil {
		return err
	}
	parts := []string{`"` + exe + `"`}
	for _, a := range args {
		parts = append(parts, quote(a))
	}
	cfg.BinaryPathName = strings.Join(parts, " ")
	return s.UpdateConfig(cfg)
}
