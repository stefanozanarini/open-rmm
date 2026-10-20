# syntax=docker/dockerfile:1
#
# open-rmm console image: openrmm-gateway (default entrypoint),
# openrmm-server, openrmm-signer and openrmm-admin. Static binaries on a
# distroless base, running as non-root. It also carries the Windows agent
# and watchdog of the same version and the modules of the repository, which
# the console signs (with the builder's keys) and publishes.

FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
# Default: the VERSION file (x.y.z). Raise it for every agent release.
ARG VERSION=
RUN v="${VERSION:-$(cat VERSION)}" \
 && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$v" \
      -o /out/ ./console/cmd/openrmm-gateway ./console/cmd/openrmm-core ./console/cmd/openrmm-server \
               ./console/cmd/openrmm-signer ./console/cmd/openrmm-admin ./console/cmd/openrmm-builder \
 && mkdir -p /agent/windows-amd64 \
 && CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w -X main.version=$v" \
      -o /agent/windows-amd64/ ./agent/cmd/openrmm-agent ./agent/cmd/openrmm-watchdog \
 && echo "$v" > /agent/VERSION

# Mount points of the signer's and the package library's volumes, owned by
# the runtime user: Docker copies ownership into a named volume the first
# time it is mounted.
RUN mkdir -p /rootfs/run/openrmm-signer /rootfs/run/openrmm-shell /rootfs/run/openrmm-builder /rootfs/var/lib/openrmm-signer /rootfs/var/lib/openrmm/packages \
 && chmod 0750 /rootfs/run/openrmm-signer /rootfs/run/openrmm-shell /rootfs/run/openrmm-builder /rootfs/var/lib/openrmm/packages \
 && chmod 0700 /rootfs/var/lib/openrmm-signer

# openrmm-builder: signs and builds agent installers with msitools/wixl and
# osslsigncode (Debian packages). Separate image, never internet-facing.
#   docker build --target builder -t open-rmm-builder .
FROM debian:bookworm-slim AS builder
RUN apt-get update \
 && apt-get install -y --no-install-recommends wixl msitools osslsigncode openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /var/lib/openrmm-builder /run/openrmm-builder \
 && chown 65532:65532 /var/lib/openrmm-builder /run/openrmm-builder \
 && chmod 0700 /var/lib/openrmm-builder && chmod 0750 /run/openrmm-builder
COPY --from=build /out/openrmm-builder /usr/local/bin/
COPY packaging/wix/openrmm-agent.wxs /usr/share/openrmm/openrmm-agent.wxs
USER 65532:65532
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/openrmm-builder", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/openrmm-builder"]

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/ /usr/local/bin/
COPY --from=build /agent/ /usr/share/openrmm/agent/
COPY modules/ /usr/share/openrmm/modules/
COPY --from=build --chown=65532:65532 /rootfs/ /
USER nonroot:nonroot
EXPOSE 8443
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/openrmm-gateway", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/openrmm-gateway"]
