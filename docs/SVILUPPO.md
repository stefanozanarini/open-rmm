# Guida allo sviluppo

## Requisiti

- Go 1.26 oppure Docker. Senza Go installato, `scripts/go-docker.sh` esegue i comandi nel container ufficiale `golang`:

  ```bash
  scripts/go-docker.sh go test ./...
  make GO="scripts/go-docker.sh go" test
  ```

- PostgreSQL 16 per i test di integrazione e per provare il gateway.

## Comandi

| Comando | Cosa fa |
|---|---|
| `make test` | Test unitari ed end-to-end (gateway TLS reale + agente) con race detector |
| `make test-integration` | Test su PostgreSQL: RLS, audit append-only, token. Richiede `OPENRMM_TEST_DATABASE_URL` |
| `make lint` | `go vet` (Linux e Windows), staticcheck, gosec |
| `make vuln` | govulncheck |
| `make build` / `make build-windows` | Eseguibili in `bin/` |
| `make tools proto` | Rigenera il codice gRPC da `proto/` |

## Database

La console **non parte** se si connette con un superutente o con un ruolo `BYPASSRLS`, perché quei ruoli ignorano la row-level security che isola i tenant. Crea un ruolo dedicato, proprietario del database:

```sql
CREATE ROLE openrmm LOGIN PASSWORD '...';
CREATE DATABASE openrmm OWNER openrmm;
```

## Prova completa in locale

```bash
export OPENRMM_DATABASE_URL='postgres://openrmm:PASSWORD@127.0.0.1:5432/openrmm?sslmode=disable'
make build

# 1. PKI: root CA, CA degli agenti, certificato del gateway
bin/openrmm-admin pki init -dir ./dev-pki -gateway-dns localhost

# 2. Schema, tenant e token di enrollment
bin/openrmm-admin db migrate
TENANT=$(bin/openrmm-admin tenant create -name "Prova")
bin/openrmm-admin token create -tenant "$TENANT" -description "prova locale"

# 3. Gateway
OPENRMM_LISTEN=127.0.0.1:8443 \
OPENRMM_TLS_CERT=dev-pki/gateway.crt OPENRMM_TLS_KEY=dev-pki/gateway.key \
OPENRMM_AGENTS_CA_CERT=dev-pki/agents-ca.crt OPENRMM_AGENTS_CA_KEY=dev-pki/agents-ca.key \
bin/openrmm-gateway
```

In un altro terminale, configura e avvia l'agente:

```json
{
  "server": "localhost:8443",
  "root_ca_file": "dev-pki/root-ca.crt",
  "enroll_token": "<token>",
  "data_dir": "/tmp/openrmm-agent"
}
```

```bash
bin/openrmm-agent run -config agent.json
bin/openrmm-admin agents list -tenant "$TENANT"
bin/openrmm-admin audit verify -tenant "$TENANT"
```

`root-ca.key` serve solo per emettere una nuova CA degli agenti: in produzione va tenuta offline.

## Configurazione dell'agente su Windows

L'agente legge, in ordine di precedenza crescente:

1. `C:\ProgramData\open-rmm\agent.json`
2. `HKLM\SOFTWARE\open-rmm` (scritto dall'MSI)
3. `HKLM\SOFTWARE\Policies\open-rmm` (scritto da GPO)

| Valore | Tipo | Esempio |
|---|---|---|
| `Server` | REG_SZ | `agent.cliente.it:443` |
| `RootCA` | REG_SZ | PEM della root CA |
| `EnrollToken` | REG_SZ | token di enrollment |
| `JobSigningKeys` | REG_MULTI_SZ | `ed25519:...` |
| `AllowAdHocScripts` | REG_DWORD | `1` (default) o `0` |

Per lo sviluppo, `openrmm-agent install -config <file>` registra il servizio con avvio automatico e azioni di ripristino (riavvio dopo 5 s, 30 s, poi ogni 2 minuti). In produzione lo farà l'MSI.
