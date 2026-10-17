#!/usr/bin/env bash
# Creates the open-rmm PKI and prepares the files the gateway container needs.
#
#   deploy/setup-pki.sh agent.cliente.it
#
# Result:
#   deploy/pki/ca/        all PKI files, including root-ca.key: MOVE THAT KEY OFFLINE
#   deploy/pki/gateway/   the four files mounted read-only into the gateway,
#                         owned by the container user (65532), mode 0400
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
docker compose run --rm --no-deps --user "$(id -u):$(id -g)" admin \
  pki init -dir /pki/ca -gateway-dns "$DNS"
docker run --rm --network none -v "$HERE/pki:/pki" --entrypoint sh postgres:16-alpine -c '
  set -e
  mkdir -p /pki/gateway
  for f in gateway.crt gateway.key agents-ca.crt agents-ca.key; do
    install -o 65532 -g 65532 -m 0400 "/pki/ca/$f" "/pki/gateway/$f"
  done
  chown 65532:65532 /pki/gateway
  chmod 0500 /pki/gateway
'

cat <<MSG

Gateway files ready in deploy/pki/gateway.
Distribute deploy/pki/ca/root-ca.crt to the agents (MSI / GPO).
Now move deploy/pki/ca/root-ca.key OFFLINE and delete it from this host.
MSG
