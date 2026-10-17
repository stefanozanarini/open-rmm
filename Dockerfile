# syntax=docker/dockerfile:1
#
# open-rmm console image: openrmm-gateway (default entrypoint) and
# openrmm-admin. Static binaries on a distroless base, running as non-root.

FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
ARG VERSION=0.0.0-dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/ ./console/cmd/openrmm-gateway ./console/cmd/openrmm-admin

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/ /usr/local/bin/
USER nonroot:nonroot
EXPOSE 8443
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/openrmm-gateway", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/openrmm-gateway"]
