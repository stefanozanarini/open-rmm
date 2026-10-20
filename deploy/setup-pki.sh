#!/usr/bin/env bash
# Creates the open-rmm PKI and prepares the files the gateway container needs.
#
#   deploy/setup-pki.sh agent.cliente.it
#
# Result:
#   deploy/pki/ca/        all PKI files, including root-ca.key: MOVE THAT KEY OFFLINE
#   deploy/pki/gateway/   files mounted into the gateway (DMZ): no private CA key
#   deploy/pki/core/      files mounted into the core (internal network)
#                         both owned by the container user (65532), mode 0400
#
# The ownership change runs in a throwaway container, so only access to
# Docker is required (no sudo).
set -euo pipefail
DNS="${1:?usage: $0 <gateway DNS name[,other names]>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"
if [ -e pki/ca ]; then
  echo "pki/ca already exists: refusing to overwrite an existing PKI" >&2
  exit 1
fi
mkdir -p pki
chmod 700 pki
docker run --rm --network none --read-only --user "$(id -u):$(id -g)" -v "$HERE/pki:/pki" \
  --entrypoint /usr/local/bin/openrmm-admin "${OPENRMM_IMAGE:-open-rmm:dev}" \
  pki init -dir /pki/ca -gateway-dns "$DNS"
docker run --rm --network none -v "$HERE/pki:/pki" --entrypoint sh postgres:16-alpine -c '
  set -e
  copy() { dir=$1; shift
    mkdir -p "/pki/$dir"
    for f in "$@"; do install -o 65532 -g 65532 -m 0400 "/pki/ca/$f" "/pki/$dir/$f"; done
    chown 65532:65532 "/pki/$dir"; chmod 0500 "/pki/$dir"
  }
  # Gateway (DMZ): its own certificate and the PUBLIC agents CA certificate.
  copy gateway gateway.crt gateway.key agents-ca.crt
  # Core (internal): agents CA with its key, tunnel certificate, root CA.
  copy core agents-ca.crt agents-ca.key core.crt core.key root-ca.crt
'

# Public: mounted into the server, which reads it for the agent installers.
chmod 0644 pki/ca/root-ca.crt

cat <<MSG

Gateway files ready in deploy/pki/gateway, core files in deploy/pki/core.
If the gateway runs on a separate DMZ host, copy deploy/pki/gateway there.
Distribute deploy/pki/ca/root-ca.crt to the agents (MSI / GPO).
Now move deploy/pki/ca/root-ca.key OFFLINE and delete it from this host.
MSG
