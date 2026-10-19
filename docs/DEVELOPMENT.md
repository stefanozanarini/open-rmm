# Development guide

## Requirements

- Go 1.26, or Docker. Without Go installed, `scripts/go-docker.sh` runs commands in the official `golang` container (build variables such as `GOOS` are forwarded):

  ```bash
  scripts/go-docker.sh go test ./...
  make GO="scripts/go-docker.sh go" test
  ```

- PostgreSQL 16 for integration tests and for trying the gateway.
- For the MSI: msitools/wixl, or Docker (`packaging/wix/build.sh` uses a container when wixl is not installed).

## Commands

| Command | What it does |
|---|---|
| `make test` | Unit and end-to-end tests (real TLS gateway + agent, fake OIDC identity provider) with the race detector |
| `make test-integration` | PostgreSQL tests: RLS, append-only audit, tokens, jobs, releases. Needs `OPENRMM_TEST_DATABASE_URL` |
| `make lint` | `go vet` (Linux and Windows), staticcheck, gosec |
| `make vuln` | govulncheck |
| `make build` / `make build-windows` | Executables in `bin/` (`VERSION=x.y.z` sets the embedded version) |
| `make msi VERSION=x.y.z` | Windows installer in `dist/` |
| `make tools proto` | Regenerates the gRPC code from `proto/` |

To look at the web console with sample data and a fake identity provider:

```bash
OPENRMM_PREVIEW=1 go test -run Preview -timeout 0 ./internal/e2e/
# then open http://127.0.0.1:18080
```

## Database

The console **refuses to start** when connected as a superuser or a `BYPASSRLS` role, because those roles ignore the row-level security that isolates tenants. Create a dedicated role owning the database:

```sql
CREATE ROLE openrmm LOGIN PASSWORD '...';
CREATE DATABASE openrmm OWNER openrmm;
```

## Full local run

```bash
export OPENRMM_DATABASE_URL='postgres://openrmm:PASSWORD@127.0.0.1:5432/openrmm?sslmode=disable'
make build

# 1. PKI: root CA, agents CA, gateway certificate
bin/openrmm-admin pki init -dir ./dev-pki -gateway-dns localhost

# 2. Schema, tenant and enrollment token
bin/openrmm-admin db migrate
TENANT=$(bin/openrmm-admin tenant create -name "Test")
bin/openrmm-admin token create -tenant "$TENANT" -auto-approve -description "local test"

# 3. Gateway
OPENRMM_LISTEN=127.0.0.1:8443 \
OPENRMM_TLS_CERT=dev-pki/gateway.crt OPENRMM_TLS_KEY=dev-pki/gateway.key \
OPENRMM_AGENTS_CA_CERT=dev-pki/agents-ca.crt OPENRMM_AGENTS_CA_KEY=dev-pki/agents-ca.key \
bin/openrmm-gateway
```

In another terminal, configure and start the agent:

```json
{
  "server": "localhost:8443",
  "root_ca_file": "dev-pki/root-ca.crt",
  "enroll_token": "<token>",
  "data_dir": "/tmp/openrmm-agent/data",
  "install_dir": "/tmp/openrmm-agent/install"
}
```

```bash
bin/openrmm-agent run -config agent.json
bin/openrmm-admin agents list -tenant "$TENANT"
bin/openrmm-admin audit verify -tenant "$TENANT"
```

`root-ca.key` is needed only to issue a new agents CA: in production keep it offline.

## Agent configuration on Windows

The agent reads, in increasing order of precedence:

1. `C:\ProgramData\open-rmm\agent.json`
2. `HKLM\SOFTWARE\open-rmm` (written by the MSI)
3. `HKLM\SOFTWARE\Policies\open-rmm` (written by Group Policy, see `packaging/admx`)

| Value | Type | Example |
|---|---|---|
| `Server` | REG_SZ | `agent.example.com:443` |
| `RootCA` | REG_SZ | root CA as PEM or single-line base64 DER |
| `EnrollToken` | REG_SZ | enrollment token (removed from the MSI key once enrolled) |
| `JobSigningKeys`, `ModuleSigningKeys`, `ReleaseSigningKeys` | REG_MULTI_SZ, or REG_SZ separated by `,` / `;` | `ed25519:...` |
| `AllowAdHocScripts` | REG_DWORD, or REG_SZ `0`/`1` | `1` (default) or `0` |
| `MaxConcurrentJobs` | REG_DWORD | `4` |

For development, `openrmm-agent install` and `openrmm-watchdog install` register the services (with recovery actions and, for the watchdog, the scheduled check). In production the MSI does this.
