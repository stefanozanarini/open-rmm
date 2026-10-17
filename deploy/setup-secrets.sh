#!/usr/bin/env bash
# Prepares the secrets of the console containers:
#
#   deploy/setup-secrets.sh <file with the Entra client secret>
#
#   secrets/server/oidc-client-secret   copied from the given file
#   secrets/signer/job-signing.key      generated here; its public key is
#                                       printed, to configure on the agents
#
# Both end up owned by the container user (65532), mode 0400. The ownership
# change runs in a throwaway container, so only Docker access is needed.
set -euo pipefail
SECRET_FILE="${1:?usage: $0 <file containing the Entra client secret>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"
mkdir -p secrets/server secrets/signer console-tls
chmod 700 secrets
if [ ! -e secrets/signer/job-signing.key ]; then
  docker compose run --rm -q --no-deps --user "$(id -u):$(id -g)" -v "$HERE/secrets/signer:/out" admin \
    signing keygen -out /out/job-signing.key
else
  echo "secrets/signer/job-signing.key exists: keeping it"
fi
install -m 0600 "$SECRET_FILE" secrets/server/oidc-client-secret
docker run --rm --network none -v "$HERE/secrets:/s" --entrypoint sh postgres:16-alpine -c '
  set -e
  chown -R 65532:65532 /s/server /s/signer
  chmod 0500 /s/server /s/signer
  chmod 0400 /s/server/oidc-client-secret /s/signer/job-signing.key
'
echo
echo "Configure the public key printed above (ed25519:...) as JobSigningKeys on the agents."
