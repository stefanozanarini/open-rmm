# Without a local Go toolchain, prefix commands with scripts/go-docker.sh,
# e.g. `make GO="scripts/go-docker.sh go" test`.
GO ?= go
VERSION ?= $(shell cat VERSION)
LDFLAGS := -s -w -X main.version=$(VERSION)

BUF_VERSION := v1.74.0
PROTOC_GEN_GO_VERSION := v1.36.12
PROTOC_GEN_GO_GRPC_VERSION := v1.6.2

.PHONY: all build build-windows msi test test-integration lint vuln proto tools

all: lint test build

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/ ./agent/cmd/... ./console/cmd/...

build-windows:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/openrmm-agent.exe ./agent/cmd/openrmm-agent
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/openrmm-watchdog.exe ./agent/cmd/openrmm-watchdog

# Windows installer (needs VERSION=x.y.z; built with msitools/wixl). Signed
# with Authenticode when SIGN_CERT and SIGN_KEY are given (openrmm-admin
# codesign); SIGN_TIMESTAMP overrides the timestamp server.
msi: build-windows
	SIGN_CERT='$(SIGN_CERT)' SIGN_KEY='$(SIGN_KEY)' SIGN_TIMESTAMP='$(SIGN_TIMESTAMP)' packaging/wix/build.sh $(VERSION)

test:
	$(GO) test -race -count=1 ./...

# Needs a disposable database owned by a non-superuser role, e.g.
#   OPENRMM_TEST_DATABASE_URL=postgres://openrmm:test@127.0.0.1:5432/openrmm?sslmode=disable
test-integration:
	@test -n "$$OPENRMM_TEST_DATABASE_URL" || (echo "OPENRMM_TEST_DATABASE_URL is not set"; exit 1)
	$(GO) test -count=1 -run Postgres ./internal/console/store/

lint:
	$(GO) vet ./...
	GOOS=windows $(GO) vet ./...
	$(GO) run honnef.co/go/tools/cmd/staticcheck@latest ./...
	$(GO) run github.com/securego/gosec/v2/cmd/gosec@latest -quiet -exclude-dir=gen ./...

vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

tools:
	$(GO) install github.com/bufbuild/buf/cmd/buf@$(BUF_VERSION)
	$(GO) install google.golang.org/protobuf/cmd/protoc-gen-go@$(PROTOC_GEN_GO_VERSION)
	$(GO) install google.golang.org/grpc/cmd/protoc-gen-go-grpc@$(PROTOC_GEN_GO_GRPC_VERSION)

proto:
	buf lint
	buf generate
