# syntax=docker/dockerfile:1
#
# open-rmm console image: openrmm-gateway (default entrypoint),
# openrmm-server, openrmm-signer and openrmm-admin. Static binaries on a
# distroless base, running as non-root.

FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
ARG VERSION=0.0.0-dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/ ./console/cmd/openrmm-gateway ./console/cmd/openrmm-core ./console/cmd/openrmm-server \
               ./console/cmd/openrmm-signer ./console/cmd/openrmm-admin

# Mount points of the signer's and the package library's volumes, owned by
# the runtime user: Docker copies ownership into a named volume the first
# time it is mounted.
RUN mkdir -p /rootfs/run/openrmm-signer /rootfs/run/openrmm-shell /rootfs/var/lib/openrmm-signer /rootfs/var/lib/openrmm/packages \
 && chmod 0750 /rootfs/run/openrmm-signer /rootfs/run/openrmm-shell /rootfs/var/lib/openrmm/packages \
 && chmod 0700 /rootfs/var/lib/openrmm-signer

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/ /usr/local/bin/
COPY --from=build --chown=65532:65532 /rootfs/ /
USER nonroot:nonroot
EXPOSE 8443
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/openrmm-gateway", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/openrmm-gateway"]
