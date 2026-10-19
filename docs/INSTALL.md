# Server installation

The console runs in containers on a Linux host with Docker and the Compose plugin. The files are in [deploy/](../deploy).

| Container | Role | Exposed |
|---|---|---|
| `gateway` | Agents endpoint (mTLS relay): no database, no CA private key | Yes, port `OPENRMM_PUBLIC_PORT` (default 443) |
| `core` | Agent sessions, enrollment, certificate issuance, job dispatch; opens the tunnel to the gateway | No |
| `db` | PostgreSQL 16 | No: internal network without outside access |
| `server` | Operators' web console | LAN only (`OPENRMM_CONSOLE_BIND`) |
| `signer` | Command signing, the only holder of the key | No: reachable only by `server` through a local socket |
| `admin` | Administration commands, on demand | No |

Every service runs as an unprivileged user (65532), with a read-only file system, no Linux capabilities, and memory and process limits. The gateway, the only internet-facing service, has no database credentials, no CA private key and no access to the signer socket: it only relays agent traffic over the tunnel that `core` opens towards it ([ARCHITECTURE.md](ARCHITECTURE.md) §6.7).

## 1. Configuration

```bash
cd deploy
cp .env.example .env
```

Set two different, URL-safe passwords in `.env` (e.g. `openssl rand -hex 24`): `POSTGRES_PASSWORD` for the database administrator and `OPENRMM_DB_PASSWORD` for the application role `openrmm`. On first start the script in `postgres-init/` creates the `openrmm` role without superuser privileges, because a superuser would bypass tenant isolation.

## 2. PKI

```bash
docker compose build
./setup-pki.sh agent.example.com
```

The script creates:

- `pki/ca/`: the whole PKI. Distribute `root-ca.crt` to the agents (MSI or GPO).
- `pki/gateway/`: the files the gateway needs (its certificate and key, the public agents CA certificate), mounted read-only.
- `pki/core/`: the files the core needs (agents CA with its key, the core tunnel certificate, the root CA), mounted read-only.

**Move `pki/ca/root-ca.key` off the server** (e.g. to an encrypted USB key kept in a safe) and delete it from the host. It is needed only to issue a new agents CA.

The DNS name (`agent.example.com`) must resolve to the host both on the LAN and on the internet. TLS is terminated by the gateway: a firewall or reverse proxy in front of it must forward the TCP connection as is (passthrough), without decrypting it.

### Gateway on a separate DMZ host

The default stack runs gateway and core on the same host. To put the gateway in a DMZ:

1. On the DMZ host: copy `deploy/dmz/compose.yaml` and the folder `deploy/pki/gateway` (no private CA key in it) to `./pki/gateway`, set `OPENRMM_TUNNEL_BIND` to the DMZ host's internal-facing address, and `docker compose up -d`.
2. On the internal host: remove the `gateway` service from the stack (or do not start it) and set in `.env` `OPENRMM_GATEWAY_TUNNEL=<dmz-host>:8444` and `OPENRMM_GATEWAY_NAME=agent.example.com` (the DNS name in the gateway certificate).
3. Firewall: internet → DMZ host port 443; internal network (core host) → DMZ host port 8444. **No rule from the DMZ to the internal network.**

The image for the DMZ host must be built (`docker compose build`) and pushed to a registry you control, or loaded with `docker save` / `docker load`; set `OPENRMM_IMAGE` accordingly.

## 3. Entra ID and secrets

Register the application in Entra ID following [ENTRA.md](ENTRA.md) and fill in the console variables in `.env`. Then save the client secret to a file and prepare the container secrets:

```bash
./setup-secrets.sh /path/to/client-secret.txt
```

The script installs the client secret for `server`, generates the job signing key for `signer` and prints its public key (`ed25519:…`), to configure on the agents as `JobSigningKeys`. Delete the secret file afterwards.

The console must be served over HTTPS, either:

- put certificate and key in `deploy/console-tls/` and set `OPENRMM_CONSOLE_TLS_CERT=/run/openrmm/tls/console.crt` and `OPENRMM_CONSOLE_TLS_KEY=/run/openrmm/tls/console.key`;
- or use an internal TLS reverse proxy in front of the console port.

## 4. Start

```bash
docker compose up -d
docker compose ps
```

Database migrations are applied automatically at startup. `docker compose logs core` should show `tunnel to gateway open`.

## 5. Tenant and enrollment tokens

```bash
docker compose run --rm admin tenant create -name "Customer"
docker compose run --rm admin token create -tenant <TENANT> -max-uses 250 -ttl 720h -description "GPO main site"
```

By default **every new agent is pending** until an operator approves it: it is connected and visible, but receives no commands. This protects against someone reading the token from the registry (GPO policy keys are readable by every domain user) and enrolling a rogue agent.

For a token you fully trust (e.g. used by a technician for a single PC) you can enable automatic approval:

```bash
docker compose run --rm admin token create -tenant <TENANT> -max-uses 1 -ttl 2h -auto-approve
```

Tokens can also be created from the web console (**Token** page, administrators only).

## 6. Managing agents

From the web console (**Agenti** page) administrators approve or revoke agents, and operators and administrators run commands; every command requires a fresh Microsoft sign-in. The same operations are available from the command line:

```bash
docker compose run --rm admin agents list    -tenant <TENANT>
docker compose run --rm admin agents approve -tenant <TENANT> -agent <AGENT>
docker compose run --rm admin agents reject  -tenant <TENANT> -agent <AGENT>
docker compose run --rm admin audit verify   -tenant <TENANT>
```

`reject` and `revoke` are equivalent: the agent is disconnected and can no longer connect.

## Signing keys

| Key | Use | Where the private part lives |
|---|---|---|
| Module release | Signs modules | Offline, on the machine where modules are signed |
| Agent release | Signs agent releases | Offline |
| Job signing | Signs the commands sent to agents | Only in the `signer` container (created by `setup-secrets.sh`) |

Offline keys are generated on the offline machine:

```bash
openrmm-admin signing keygen -out module-release.key
openrmm-admin signing keygen -out agent-release.key
```

The command prints the public key (`ed25519:…`). Public keys are configured on the agents (`module_signing_keys`, `job_signing_keys`, `release_signing_keys` in the configuration file, or the `ModuleSigningKeys`, `JobSigningKeys`, `ReleaseSigningKeys` registry values through MSI or GPO). To publish modules and releases, also set `OPENRMM_MODULE_KEYS` and `OPENRMM_RELEASE_KEYS`. See [MODULES.md](MODULES.md) and [UPDATES.md](UPDATES.md).

## Agent certificates

Agent certificates last 90 days. The agent renews its certificate when less than a third of the validity is left (about 30 days), generating a new key each time. The previous certificate stays valid until the agent first connects with the new one, so a lost renewal response cannot lock it out.

A PC switched off for more than 90 days has an expired certificate: if its configuration still holds a valid token it enrolls again (as a new agent), otherwise it must be reinstalled with a new token.

## Backup

The `db-data` volume holds the whole console state. Take regular encrypted backups, for example:

```bash
docker compose exec db pg_dump -U postgres -Fc openrmm > openrmm-$(date +%F).dump
```
