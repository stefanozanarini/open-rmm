//go:build !windows

package svcctl

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// execPathRe extracts path= from "systemctl show -p ExecStart --value".
var execPathRe = regexp.MustCompile(`path=(\S+)`)

// Systemd is the Linux implementation. The executable of each unit is set by
// a drop-in, /etc/systemd/system/<unit>.service.d/50-openrmm-version.conf,
// so the packaged unit file never changes.
type Systemd struct {
	// Root of the systemd configuration (tests); default /etc/systemd/system.
	Root string
}

// New returns the platform Manager.
func New() Manager { return Systemd{Root: "/etc/systemd/system"} }

func systemctl(args ...string) ([]byte, error) {
	exe := "/usr/bin/systemctl"
	if _, err := os.Stat(exe); err != nil {
		exe = "/bin/systemctl"
	}
	return exec.Command(exe, args...).CombinedOutput() // #nosec G204 -- fixed binary, unit names are constants
}

func (Systemd) Running(name string) (bool, error) {
	out, err := systemctl("is-active", name+".service")
	state := strings.TrimSpace(string(out))
	if state == "active" || state == "activating" || state == "reloading" {
		return true, nil
	}
	var ee *exec.ExitError
	if err != nil && !errors.As(err, &ee) {
		return false, err
	}
	return false, nil
}

func (Systemd) Start(name string) error {
	if out, err := systemctl("start", name+".service"); err != nil {
		return fmt.Errorf("systemctl start %s: %v: %s", name, err, out)
	}
	return nil
}

func (Systemd) Stop(name string, _ time.Duration) error {
	if out, err := systemctl("stop", name+".service"); err != nil {
		return fmt.Errorf("systemctl stop %s: %v: %s", name, err, out)
	}
	return nil
}

func (d Systemd) dropIn(name string) string {
	return filepath.Join(d.Root, name+".service.d", "50-openrmm-version.conf")
}

func (d Systemd) Binary(name string) (string, error) {
	f, err := os.Open(d.dropIn(name))
	if errors.Is(err, os.ErrNotExist) && d.Root == "/etc/systemd/system" {
		// No version drop-in yet: the packaged unit's ExecStart applies.
		out, err := systemctl("show", "-p", "ExecStart", "--value", name+".service")
		if err != nil {
			return "", fmt.Errorf("systemctl show %s: %v", name, err)
		}
		if m := execPathRe.FindStringSubmatch(string(out)); m != nil {
			return m[1], nil
		}
		return "", fmt.Errorf("cannot read ExecStart of %s", name)
	}
	if err != nil {
		return "", fmt.Errorf("version drop-in for %s: %w", name, err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(strings.TrimSpace(sc.Text()), "ExecStart="); ok && v != "" {
			exe, _, _ := strings.Cut(v, " ")
			return exe, nil
		}
	}
	return "", fmt.Errorf("no ExecStart in %s", d.dropIn(name))
}

func (d Systemd) SetBinary(name, exe string, args []string) error {
	for _, s := range append([]string{exe}, args...) {
		if strings.ContainsAny(s, " \t\n\"'\\%$;") {
			return fmt.Errorf("unsupported character in %q", s)
		}
	}
	p := d.dropIn(name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil { // #nosec G301 -- systemd configuration directory
		return err
	}
	content := "# Managed by open-rmm: selects the installed version.\n[Service]\nExecStart=\nExecStart=" +
		strings.Join(append([]string{exe}, args...), " ") + "\n"
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil { // #nosec G306 -- systemd units are world-readable
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		return err
	}
	if d.Root == "/etc/systemd/system" {
		if out, err := systemctl("daemon-reload"); err != nil {
			return fmt.Errorf("systemctl daemon-reload: %v: %s", err, out)
		}
	}
	return nil
}
