#!/usr/bin/env bash
# Esegue il toolchain Go in un container, per chi non ha Go installato.
# Uso: scripts/go-docker.sh go test ./...
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${GO_IMAGE:-golang:1.26-bookworm}"
exec docker run --rm -i \
  -u "$(id -u):$(id -g)" \
  -v "$ROOT:/src" -w /src \
  -v openrmm-gocache:/cache \
  -e GOCACHE=/cache/build -e GOMODCACHE=/cache/mod -e GOPATH=/cache/gopath \
  -e HOME=/tmp \
  ${GO_DOCKER_ARGS:-} \
  "$IMAGE" "$@"
