#!/usr/bin/env bash
# Builds dist/openrmm-agent-<version>-x64.msi from bin/openrmm-agent.exe and
# bin/openrmm-watchdog.exe (make build-windows VERSION=<version>), on Linux,
# with msitools/wixl in a container.
#
#   packaging/wix/build.sh 1.2.0
set -euo pipefail
VERSION="${1:?usage: $0 <version x.y.z>}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "version must be x.y.z" >&2; exit 1
fi
for f in openrmm-agent.exe openrmm-watchdog.exe; do
  [ -f "$ROOT/bin/$f" ] || { echo "missing bin/$f: run make build-windows VERSION=$VERSION" >&2; exit 1; }
  file "$ROOT/bin/$f" | grep -q "PE32+" || { echo "bin/$f is not a Windows executable" >&2; exit 1; }
done
mkdir -p "$ROOT/dist"
OUT="dist/openrmm-agent-$VERSION-x64.msi"
# Use the local wixl when installed (CI), otherwise a container.
if command -v wixl >/dev/null && command -v msibuild >/dev/null; then
  RUN=(sh -ec)
  cd "$ROOT"
else
  docker build -q -t openrmm-wixl -f "$ROOT/packaging/wix/Dockerfile.wixl" "$ROOT/packaging/wix" >/dev/null
  RUN=(docker run --rm -u "$(id -u):$(id -g)" -v "$ROOT:/src" -w /src openrmm-wixl sh -ec)
fi
"${RUN[@]}" "
  wixl -a x64 -D Version=$VERSION -D BinDir=bin -o '$OUT' packaging/wix/openrmm-agent.wxs
  # wixl does not let the source declare SecureCustomProperties: add ours so
  # the configuration properties reach the elevated install.
  cur=\$(msiinfo export '$OUT' Property | awk -F'\t' '\$1==\"SecureCustomProperties\"{print \$2}')
  props='SERVER;ENROLLTOKEN;ROOTCA;JOBSIGNINGKEYS;MODULESIGNINGKEYS;RELEASESIGNINGKEYS;ALLOWADHOCSCRIPTS'
  msibuild '$OUT' -q \"UPDATE Property SET Value='\$cur;\$props' WHERE Property='SecureCustomProperties'\"
"
echo "$OUT"
