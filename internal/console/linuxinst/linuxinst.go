// Package linuxinst builds the Linux agent installer: a shell script with a
// tar.gz payload (agent, watchdog, systemd units, configuration), the Linux
// counterpart of the preconfigured MSI. It needs only sh, tar and systemd,
// so the same file installs on Debian, Ubuntu, RHEL and its rebuilds, and
// SUSE.
package linuxinst

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"regexp"
	"strings"
	"text/template"

	"github.com/stefanozanarini/open-rmm/internal/agent/config"
	linuxunits "github.com/stefanozanarini/open-rmm/packaging/linux"
)

// Settings are the values preset in the installer.
type Settings struct {
	Server, RootCA, EnrollToken      string
	JobKeys, ModuleKeys, ReleaseKeys string // separated by , or ;
}

// Arch maps a platform to the uname -m values it runs on.
var archs = map[string]string{"linux/amd64": "x86_64", "linux/arm64": "aarch64"}

// Platforms are the platforms an installer can be built for.
func Platforms() []string { return []string{"linux/amd64", "linux/arm64"} }

// FileName is the installer's name.
func FileName(version, platform string) string {
	return "openrmm-agent-" + version + "-" + strings.ReplaceAll(platform, "/", "-") + ".run"
}

var versionRe = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)

// Build writes the installer. agent and watchdog are the executables of a
// published release of version for platform.
func Build(w io.Writer, version, platform string, agent, watchdog []byte, s Settings) error {
	machine, ok := archs[platform]
	if !ok {
		return fmt.Errorf("unsupported platform %q", platform)
	}
	if !versionRe.MatchString(version) {
		return fmt.Errorf("invalid version %q", version)
	}
	cfg, err := json.MarshalIndent(config.Config{Server: s.Server, RootCAPEM: s.RootCA, EnrollToken: s.EnrollToken,
		JobSigningKeys: config.SplitList(s.JobKeys), ModuleSigningKeys: config.SplitList(s.ModuleKeys),
		ReleaseSigningKeys: config.SplitList(s.ReleaseKeys)}, "", "  ")
	if err != nil {
		return err
	}
	var payload bytes.Buffer
	gz := gzip.NewWriter(&payload)
	tw := tar.NewWriter(gz)
	add := func(name string, mode int64, data []byte) error {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		_, err := tw.Write(data)
		return err
	}
	files := []struct {
		name string
		mode int64
		data []byte
	}{{"openrmm-agent", 0o755, agent}, {"openrmm-watchdog", 0o755, watchdog}, {"agent.json", 0o600, append(cfg, '\n')}}
	for _, f := range files {
		if err := add(f.name, f.mode, f.data); err != nil {
			return err
		}
	}
	units, err := fs.Glob(linuxunits.Units, "openrmm-*")
	if err != nil {
		return err
	}
	for _, u := range units {
		b, err := fs.ReadFile(linuxunits.Units, u)
		if err != nil {
			return err
		}
		if err := add("units/"+u, 0o644, b); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	if err := script.Execute(w, map[string]string{"Version": version, "Platform": platform, "Machine": machine}); err != nil {
		return err
	}
	_, err = w.Write(payload.Bytes())
	return err
}

// The script ends with the __PAYLOAD__ line; the archive follows.
var script = template.Must(template.New("run").Parse(`#!/bin/sh
# open-rmm agent {{.Version}} for {{.Platform}}: installer preconfigured by
# the console. Run as root:  sudo sh {{"$"}}0
# The agent appears in the console pending approval. Remove it with
# /opt/open-rmm/uninstall.sh.
set -eu
VERSION={{.Version}}
case "$(id -u)" in 0) ;; *) echo "Run as root: sudo sh $0" >&2; exit 1 ;; esac
if [ "$(uname -m)" != {{.Machine}} ]; then
  echo "This installer is for {{.Platform}} ({{.Machine}}), this system is $(uname -m)." >&2
  exit 1
fi
if ! command -v systemctl >/dev/null 2>&1 || [ ! -d /run/systemd/system ]; then
  echo "systemd is required." >&2
  exit 1
fi
umask 022
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
line=$(awk '/^__PAYLOAD__$/ { print NR + 1; exit }' "$0")
tail -n +"$line" "$0" | tar -xzf - -C "$tmp"

dir=/opt/open-rmm/versions/$VERSION
install -d -m 0755 /opt/open-rmm /opt/open-rmm/versions "$dir"
install -m 0755 "$tmp/openrmm-agent" "$tmp/openrmm-watchdog" "$dir/"
install -d -m 0700 /etc/open-rmm /var/lib/open-rmm
# A configuration already there (reinstall, upgrade) is kept: the agent has
# enrolled with it.
if [ -f /etc/open-rmm/agent.json ]; then
  echo "Keeping the existing /etc/open-rmm/agent.json."
else
  install -m 0600 "$tmp/agent.json" /etc/open-rmm/agent.json
fi
for u in "$tmp"/units/*; do
  install -m 0644 "$u" /etc/systemd/system/
done
# Version selection, as the watchdog writes it after an update. A newer
# version already installed by a self-update is kept.
for svc in agent watchdog; do
  d=/etc/systemd/system/openrmm-$svc.service.d
  conf=$d/50-openrmm-version.conf
  if [ -f "$conf" ]; then
    current=$(sed -n 's|^ExecStart=/opt/open-rmm/versions/\([^/]*\)/.*|\1|p' "$conf")
    if [ -n "$current" ] && [ -x "/opt/open-rmm/versions/$current/openrmm-$svc" ] &&
      [ "$(printf '%s\n%s\n' "$current" "$VERSION" | sort -V | tail -n 1)" = "$current" ]; then
      continue
    fi
  fi
  install -d -m 0755 "$d"
  printf '# Managed by open-rmm: selects the installed version.\n[Service]\nExecStart=\nExecStart=%s run -config /etc/open-rmm/agent.json\n' \
    "$dir/openrmm-$svc" >"$conf.tmp"
  chmod 0644 "$conf.tmp"
  mv "$conf.tmp" "$conf"
done
cat >/opt/open-rmm/uninstall.sh <<'UNINSTALL'
#!/bin/sh
# Removes the open-rmm agent, its state and its private key. Revoke the
# agent in the console afterwards.
set -u
case "$(id -u)" in 0) ;; *) echo "Run as root." >&2; exit 1 ;; esac
systemctl disable --now openrmm-healthcheck.timer openrmm-watchdog.service openrmm-agent.service 2>/dev/null
rm -rf /etc/systemd/system/openrmm-agent.service /etc/systemd/system/openrmm-watchdog.service \
  /etc/systemd/system/openrmm-healthcheck.service /etc/systemd/system/openrmm-healthcheck.timer \
  /etc/systemd/system/openrmm-agent.service.d /etc/systemd/system/openrmm-watchdog.service.d
systemctl daemon-reload
rm -rf /opt/open-rmm /var/lib/open-rmm /etc/open-rmm
echo "open-rmm agent removed."
UNINSTALL
chmod 0700 /opt/open-rmm/uninstall.sh
systemctl daemon-reload
systemctl enable openrmm-agent.service openrmm-watchdog.service openrmm-healthcheck.timer >/dev/null
systemctl restart openrmm-watchdog.service openrmm-agent.service
systemctl start openrmm-healthcheck.timer
echo "open-rmm agent $VERSION installed: it appears in the console pending approval."
exit 0
__PAYLOAD__
`))
