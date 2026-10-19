#!/usr/bin/env bash
# Builds dist/openrmm-agent-<version>-x64.msi from bin/openrmm-agent.exe and
# bin/openrmm-watchdog.exe (make build-windows VERSION=<version>), on Linux,
# with msitools/wixl in a container.
#
#   packaging/wix/build.sh 1.2.0
#
# With SIGN_CERT (PEM, signing certificate first, then its CAs) and SIGN_KEY
# (PKCS#8 PEM, from openrmm-admin codesign) the executables and the MSI are
# signed with Authenticode. SIGN_TIMESTAMP is the RFC 3161 timestamp server
# (default http://timestamp.digicert.com; "none" to skip, not recommended:
# signatures without a timestamp stop being valid when the certificate
# expires).
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
SIGN=0
MOUNTS=()
if [ -n "${SIGN_CERT:-}" ] || [ -n "${SIGN_KEY:-}" ]; then
  for f in "${SIGN_CERT:-}" "${SIGN_KEY:-}"; do
    [ -f "$f" ] || { echo "SIGN_CERT and SIGN_KEY must both name existing files" >&2; exit 1; }
  done
  SIGN=1
fi
TS="${SIGN_TIMESTAMP:-http://timestamp.digicert.com}"
[ "$TS" = none ] && TS=""
if [[ -n "$TS" && ! "$TS" =~ ^https?://[A-Za-z0-9./:_-]+$ ]]; then
  echo "invalid SIGN_TIMESTAMP" >&2; exit 1
fi
# Use the local wixl when installed (CI), otherwise a container.
if command -v wixl >/dev/null && command -v msibuild >/dev/null; then
  RUN=(sh -ec)
  cd "$ROOT"
  CERT="${SIGN_CERT:-}"; KEY="${SIGN_KEY:-}"
else
  docker build -q -t openrmm-wixl -f "$ROOT/packaging/wix/Dockerfile.wixl" "$ROOT/packaging/wix" >/dev/null
  CERT=/run/sign/cert.pem; KEY=/run/sign/key.pem
  if [ "$SIGN" = 1 ]; then
    MOUNTS=(-v "$(realpath "$SIGN_CERT"):$CERT:ro" -v "$(realpath "$SIGN_KEY"):$KEY:ro")
  fi
  RUN=(docker run --rm -u "$(id -u):$(id -g)" -v "$ROOT:/src" "${MOUNTS[@]}" -w /src openrmm-wixl sh -ec)
fi
"${RUN[@]}" "
  sign() {
    osslsigncode sign -certs '$CERT' -key '$KEY' -h sha256 -n 'open-rmm agent' \\
      -i https://github.com/stefanozanarini/open-rmm ${TS:+-ts '$TS'} -in \"\$1\" -out \"\$1.signed\" >/dev/null
    mv \"\$1.signed\" \"\$1\"
  }
  bindir=bin
  if [ $SIGN = 1 ]; then
    # Sign copies: bin/ stays as built, so the build can be repeated.
    rm -rf build/signed && mkdir -p build/signed
    cp bin/openrmm-agent.exe bin/openrmm-watchdog.exe build/signed/
    sign build/signed/openrmm-agent.exe
    sign build/signed/openrmm-watchdog.exe
    bindir=build/signed
  fi
  wixl -a x64 -D Version=$VERSION -D BinDir=\$bindir -o '$OUT' packaging/wix/openrmm-agent.wxs
  # wixl does not let the source declare SecureCustomProperties: add ours so
  # the configuration properties reach the elevated install.
  cur=\$(msiinfo export '$OUT' Property | awk -F'\t' '\$1==\"SecureCustomProperties\"{print \$2}')
  props='SERVER;ENROLLTOKEN;ROOTCA;JOBSIGNINGKEYS;MODULESIGNINGKEYS;RELEASESIGNINGKEYS;ALLOWADHOCSCRIPTS'
  msibuild '$OUT' -q \"UPDATE Property SET Value='\$cur;\$props' WHERE Property='SecureCustomProperties'\"
  if [ $SIGN = 1 ]; then sign '$OUT'; fi
"
echo "$OUT"
