# open-rmm — Architecture

> Status: draft v1.1 — 2026-10-19
> First customer: ~200 Windows endpoints (clients and servers), mixed Dell / Lenovo / Acer fleet, BitLocker widely used, laptops also working off-site, console hosted at the customer and reachable from the internet. A managed-service-provider deployment (one central console federating several customer consoles) is a design goal from day one.

Legend: ✅ implemented · 🔜 next · 📋 planned

---

## 1. Goals and constraints

| # | Requirement | Notes |
|---|---|---|
| R1 | Windows clients and servers, Linux | Windows first; Linux later |
| R2 | Deployment through Group Policy | MSI + ADMX templates (§10) ✅ |
| R3 | Security as a primary requirement | §6 |
| R4 | Automatic restart after crashes | Service recovery + watchdog + scheduled check (§5) ✅ |
| R5 | Central console, multi-tenant, federable | §9 |
| R6 | Windows Update: detection and installation | Module (§8.5) |
| R7 | Hardware and software inventory, logon events | Modules (§8.1, §8.2) |
| R8 | Third-party software and firmware updates | winget, vendor tools (§8.6, §8.8) |
| R9 | PowerShell commands from the console | `script` module ✅ (§7), interactive shell ✅ (§8.11) |
| R10 | **Modular agent: new features never require an agent update** | Core principle (§3) ✅ |
| R11 | Automatic agent update | A/B with rollback (§5) ✅ |
| R12 | Operators sign in with Microsoft 365 (Entra ID); MFA mandatory | §6.6 ✅ |
| R13 | Console at the customer, reachable from the internet; **all connections start from the endpoints** | §4, §6.7 |
| R14 | Coexistence with WSUS and Intune | Observation mode (§8.5) |
| R15 | Configurable reboots per endpoint group | §8.9 |
| R16 | Separate client and server views, distinguished by OS | §11 |
| R17 | Software distribution by uploading an MSI | §8.7 |
| R18 | Dashboards of the endpoints that most need updates (Windows and third-party) | §11 |
| R19 | **Everything doable on a customer console is doable from the central console** | §9 |
| R20 | Guided first-time setup, optional enterprise CA and Active Directory integration | §12 |

**Guiding principles**

1. **The agent core knows no feature.** It communicates, authenticates, verifies signatures, evaluates simple policy conditions and runs modules. Everything else — inventory, Windows Update, Trend Micro checks, logon monitoring — is a signed module (plugin).
2. **No listening port on endpoints.** All connections start from the agent; the console never connects to a PC.
3. **A compromised console must not be enough to run arbitrary code** on endpoints (§6.3).
4. **Tenant-aware from day zero**, even with a single customer.
5. **Inward connections only from outside in:** the internet-facing part never holds the keys to the internal one (§6.7).

---

## 2. Components

```
┌─────────────────────────────── ENDPOINT ───────────────────────────────┐
│ openrmm-watchdog (service) ──supervises / applies updates──► openrmm-agent│
│                                                    (service, core)      │
│                         runs signed modules ◄──────────┘   ▲ named pipe │
│                         (child processes)                  │ (planned)  │
│                                             openrmm-userhelper (session)│
└────────────────────────────────────┬───────────────────────────────────┘
                                     │ gRPC over HTTP/2, mTLS, port 443
                                     │ (always opened by the agent)
┌──────────────── DMZ ───────────────▼───────────────────────────────────┐
│ openrmm-gateway  (relay: no database credentials, no CA key)            │
└────────────────────────────────────▲───────────────────────────────────┘
                                     │ mTLS, opened from the LAN side
┌──────────────── LAN ───────────────┴───────────────────────────────────┐
│ openrmm-core  (agent sessions, enrollment, job dispatch) ──► PostgreSQL │
│ openrmm-server (web console)  ──► openrmm-signer (job signing key)      │
│ federation link ──(outbound, mTLS)──► central console (optional)        │
└────────────────────────────────────────────────────────────────────────┘
```

The DMZ / internal split is implemented ✅ (§6.7): `openrmm-gateway` is a relay, `openrmm-core` holds the logic, the database credentials and the agents CA key.

### 2.1 Endpoint

| Component | Role | Expected update frequency |
|---|---|---|
| `openrmm-agent` ✅ | Core: transport, identity, signature checks, module cache and runner, job outbox, policy scheduler, health file | Rare (protocol or security fixes) |
| `openrmm-watchdog` ✅ | Restarts the agent when stopped or hung, applies staged updates with rollback | Very rare |
| `openrmm-userhelper` 📋 | Process in the user session: notifications, reboot prompts, modules in user context (per-user apps, per-user winget) | Rare |
| Modules ✅ | Every feature | Often, **without touching the agent** |

### 2.2 Console

| Component | Technology |
|---|---|
| `openrmm-gateway` ✅ | Go, gRPC; internet-facing relay for the agents (§6.7) |
| `openrmm-core` ✅ | Go; agent sessions, enrollment and certificate issuance, job dispatch; opens the tunnel to the gateway |
| `openrmm-server` ✅ | Go web console: server-rendered pages (html/template), no third-party JavaScript, strict CSP |
| `openrmm-signer` ✅ | Separate container holding the job signing key, reachable only through a local socket (§6.3) |
| `openrmm-admin` ✅ | Administration CLI (bootstrap, PKI, releases, modules) |
| Database ✅ | PostgreSQL 16 with row-level security per `tenant_id`; job queue and wake-ups with `LISTEN/NOTIFY` |
| Deployment ✅ | Docker Compose on Linux; all services non-root, read-only file system, no capabilities |

### 2.3 Repository layout

```
/proto                 protobuf definitions (agent ↔ console, signer)
/gen                   generated code (committed)
/agent/cmd             openrmm-agent, openrmm-watchdog
/console/cmd           openrmm-gateway, openrmm-core, openrmm-server, openrmm-signer, openrmm-admin
/internal
  /pki /signing /tlsconf /ids /release /modules   shared crypto, identity, release and module formats
  /agent/...           agent core: config, identity, client, jobs, executor, runner, modcache,
                       updater, watchdog, svcctl, winsvc, health, secfile, hostinfo
  /console/...         gateway (agent service run by the core), relay, store, audit, authn,
                       jobreq, signer, web
  /e2e                 end-to-end tests (real TLS, fake identity provider)
/modules               modules and SDKs (PowerShell, sh)
/packaging             wix (MSI), admx (GPO templates), linux (systemd units)
/deploy                Docker Compose stack and setup scripts
/docs                  documentation (English)
```

Code, identifiers, comments, documentation and commit messages are in English. The web console UI is currently in Italian.

---

## 3. Modularity (R10)

### 3.1 What is in the core

- connection to the console, reconnection with backoff;
- agent identity (certificate, renewal);
- verification of job, module and release signatures;
- module download, cache and per-run integrity check;
- running modules as child processes with timeouts, output limits and process-tree kill;
- final results outbox;
- ✅ **policy scheduler with declarative conditions** (§3.7);
- health file for the watchdog.

Everything else is a module, including PowerShell execution.

### 3.2 Module types

| Type | When | Examples |
|---|---|---|
| Signed PowerShell module ✅ | Most Windows features: fast to write, direct COM/WMI/registry access | inventory, logon events, Windows Update (WUA COM API), winget (Microsoft.WinGet.Client), BitLocker, Trend Micro checks |
| Signed native binary (Go) ✅ | Performance, heavy parsing, cross-platform | event collection at scale, firmware catalogs, Linux |
| Signed sh module ✅ | Linux | `sysinfo` |
| WebAssembly 📋 | Strong sandbox for third-party modules | — |

### 3.3 Module manifest ✅

Each module is a zip archive with a manifest signed with the offline **module release key** (Ed25519). The manifest declares the entrypoint per platform, actions and timeouts, capabilities, and the SHA-256 of the archive and of every file. A job pins the SHA-256 of the signed manifest, so the agent runs exactly the approved version. Format and checks: [MODULES.md](MODULES.md).

### 3.4 Core ↔ module protocol ✅

The core starts the module in a temporary working directory with a minimal environment and writes one JSON request line on stdin. The module writes JSON lines on stdout — `progress`, `log` and exactly one final `result` or `error`. Size limits and timeouts are enforced; on violation the core kills the whole process tree (process group on Linux, Job Object on Windows). The SDKs hide the protocol. Each module also gets a private **state directory** that persists between runs (`state_dir`, e.g. a read position); runs of the same module are serialized so it is never shared by two runs.

### 3.5 Lifecycle of a new feature

1. Write the module (PowerShell, Go or sh).
2. Sign it with the module release key, offline.
3. Publish it on the console; assign it through jobs or policies.
4. Agents download it when first needed, verify signature and hashes, cache it.

The agent is updated only when the core↔module protocol changes or for core security fixes.

### 3.6 Jobs ✅

A job is `{job_id, tenant_id, agent_id, module, version, module_sha256, action, params, not_before, expires, nonce}`, signed by `openrmm-signer`.

- Queued in the database and delivered on the agent's stream as soon as it is connected and approved (`LISTEN/NOTIFY`, with a fallback check at every heartbeat).
- Final updates go through an on-disk outbox and are re-sent until the console acknowledges them.
- A job delivered again after a reconnection is never re-run: the agent reports the state it knows.

### 3.7 Policies and conditional plugins ✅

Recurring work (inventory every 24 h, Trend Micro status every 15 min, logon events every 5 min) and automatic plugin activation are expressed as **policies**. A policy is a canonical JSON document:

```json
{"id":"…","tenant_id":"…","name":"security-baseline","version":7,"applies_to":"all",
 "rules":[
  {"id":"trend-swp","module":"trendmicro-endpoint","module_version":"1.0.0","module_sha256":"…",
   "action":"status","every_seconds":900,"when":{"service_exists":"ds_agent"}},
  {"id":"logons","module":"accesslog","module_version":"1.0.0","module_sha256":"…",
   "action":"collect","every_seconds":300}]}
```

- `applies_to` is `all`, `clients` or `servers` (OS installation type reported by the agent). 📋 Groups by site or OU.
- A policy is **signed by the signer** (domain `openrmm/policy/v1`) after an operator with the **Admin** role approves it with a fresh MFA sign-in whose nonce is the document's fingerprint — once per policy version, not at every run. Each change or deletion creates a new version; versions are immutable in the database and audited.
- The core evaluates only **declarative conditions**: `service_exists`, `file_exists`, `registry_key_exists` (HKLM), `os_family`, combined with `all`, `any`, `not` (depth ≤ 4). No product-specific logic enters the core. Results are cached for 5 minutes.
- The module is fetched only when a rule is due and its condition holds: endpoints without Trend Micro never download the Trend module. This is how "agent detects Trend Micro → downloads and enables the plugin" works without enlarging the core. Modules are pinned by manifest hash.
- The agent refuses policies for another tenant, with an invalid signature, or older than a version it has already seen (no rollback by a compromised console). Policies are stored in `policies.json` and keep running offline; results go through the outbox and are shown on the agent page.
- A rule may have a **maintenance window** in the endpoint's local time, e.g. `"window": {"days": ["sat","sun"], "start": "22:00", "end": "05:00"}` (a window crossing midnight belongs to the day it starts); a due rule waits for the next window.
- Intervals are between 1 minute and 7 days; the first run of a new rule is delayed by a random amount (up to 2 minutes) so a fleet does not run it all at once.
- Modules with the `adhoc_script` capability are refused in policies, both by the console and by the agent.

---

## 4. Agent ↔ console communication

- ✅ **gRPC over HTTP/2 with mTLS**, port 443, bidirectional stream **opened by the agent**; heartbeat every 60 s; reconnection with exponential backoff and jitter.
- ✅ Modules and releases are streamed over the authenticated connection; agent releases are downloadable only by agents targeted for them.
- 📋 HTTP(S) proxy support (CONNECT, system proxy settings).
- ✅ The console never contacts endpoints: commands travel on the stream the agent keeps open. Off-site laptops connect directly over the internet, no VPN; a single DNS name (e.g. `agent.example.com`) resolves both on the LAN and on the internet.
- 📋 Wake-on-LAN is sent by another agent on the same subnet on the console's behalf.
- Off-site, large downloads (Windows updates, winget packages, firmware) come from the vendors; the console only supplies signed metadata (hashes) to verify them.

### 4.1 Enrollment ✅

1. MSI properties or GPO (ADMX) provide server, root CA and enrollment token.
2. The agent generates its key pair locally (📋 TPM; today a file readable only by SYSTEM/Administrators) and sends a CSR with the token. Tokens are tenant-bound, expiring, use-limited, stored as hashes, rate-limited per IP.
3. The console issues a client certificate carrying `tenant_id` and `agent_id` (URI SAN).
4. New agents are **pending** until an operator approves them, unless the token auto-approves. Pending agents can connect and are visible, but receive no jobs.
5. Certificates last 90 days and are renewed automatically with a new key when a third of the validity is left; the previous certificate stays valid until the new one is first used.
6. Revocation disconnects agents immediately, even mid-session.
7. The agent pins the open-rmm root CA; the system trust store is never used.

---

## 5. Resilience and agent updates ✅

### 5.1 Restart

| Level | Windows | Linux |
|---|---|---|
| 1 | Service recovery actions (restart after 5 s, 30 s, then every 2 min) | `Restart=always` |
| 2 | Watchdog: restarts the agent when stopped or when its health file is stale for 5 min (max 6 restarts/hour) | same |
| 3 | Scheduled task every 15 min running only `sc.exe start` | `openrmm-healthcheck.timer` with `systemctl start` |

### 5.2 Agent updates

- Releases (agent + watchdog) are signed with the offline **agent release key**; the agent refuses any version not newer than itself.
- Side-by-side installation in `versions/<x.y.z>`; the watchdog switches the service executable (Windows `ImagePath`, systemd drop-in) and rolls back if the new version does not reconnect within 10 minutes; rolled-back versions are never retried.
- The new agent then updates the watchdog the same way; the two never switch at the same time.
- Rollout by ring (`pilot`, `broad`) per tenant and platform. 📋 automatic pause above a failure threshold.

Details: [UPDATES.md](UPDATES.md).

---

## 6. Security

### 6.1 Threat model (summary)

| Threat | Mitigation |
|---|---|
| Compromised console used to run code everywhere | Jobs signed only by the signer after per-job MFA (§6.3); modules and releases signed offline; local policies the console cannot change (§6.4) |
| Compromised DMZ host | The DMZ relay holds no database credentials and no CA key; the LAN side opens the connection; forwarded identities are re-verified by the core (§6.7) |
| Rogue agent enrollment | Tenant-bound, expiring, use-limited tokens; new agents pending approval |
| Man-in-the-middle | mTLS, pinned private root CA |
| Local tampering with the agent | Restricted ACLs on files, registry and pipes; module cache re-verified before each run; Authenticode-signed binaries and MSI (§12) |
| Tampered module, package or release | Ed25519 signatures and SHA-256 checked **before** anything runs |
| Job replay | Nonce, expiry and agent id in the signed payload; persistent replay cache |
| Operator abuse | Roles, per-job MFA, immutable hash-chained audit log; 📋 four-eyes approval for mass actions |
| Supply chain | Few dependencies, `govulncheck`, `gosec`, `staticcheck` in CI; 📋 SBOM, reproducible builds |

### 6.2 Keys

| Key | Where | Signs |
|---|---|---|
| Root CA | Offline | Agents CA |
| Agents CA | `openrmm-core` only (the gateway has the public certificate) | Agent, gateway and core certificates |
| Module release | Offline | Module manifests |
| Agent release | Offline | Agent releases |
| Job signing | `openrmm-signer` only (📋 HSM) | Jobs and policies |
| Code signing (Authenticode) | Enterprise CA, dedicated CA or public CA (§12) | Windows executables and MSI |

### 6.3 Job signing ✅

The signer signs a job only if the request carries an id_token issued by Entra ID **for that exact request** (the OIDC `nonce` is the canonical hash of agent, module, manifest hash, action, parameters and validity), recent, with MFA, by an operator with the Operator or Admin role for that tenant, and never used before. The signer verifies all of this itself, with Microsoft's public keys; it does not trust the console.

One approval may target **several agents** (up to 500, e.g. distributing a package): the agent list is part of the approved hash, and the signer issues one signed job per agent. Jobs may pin **packages** of the library by SHA-256, file name and size; the agent downloads them only for that job and checks size and hash before running the module.

### 6.4 Local policies on the endpoint ✅

Set by MSI or GPO, never by the console: `AllowAdHocScripts` (default on), `MaxConcurrentJobs`, trusted keys. An endpoint with `AllowAdHocScripts=0` refuses ad-hoc scripts whatever the console asks.

### 6.5 Secure development

`go vet`, `staticcheck`, `gosec`, `govulncheck`, race detector and end-to-end tests in CI; 📋 fuzzing of the parsers; no secrets in logs.

### 6.6 Operator authentication ✅

- Entra ID only (OIDC authorization code + PKCE); the console never sees passwords.
- App roles `OpenRMM.Admin`, `OpenRMM.Operator`, `OpenRMM.Reader`; assignment required.
- MFA proven by the `amr` claim, or by a Conditional Access authentication context (`acrs`, recommended with Entra ID P1) required at sign-in and for every command.
- **Per-command step-up:** every command an operator launches requires a fresh sign-in (`prompt=login`) bound to that command, by the same operator.
- Server-side sessions (only hashes stored), id rotated at login, idle and absolute expiry, CSRF token and Origin check, strict CSP.
- 📋 Break-glass account: one local FIDO2-only account, LAN only, alert on every use.

Setup: [ENTRA.md](ENTRA.md).

### 6.7 Exposure: DMZ and internal network ✅

Only the agents endpoint is meant for the internet; the web console stays on the operators' LAN/VPN (📋 or behind Entra Application Proxy).

```
internet ──► [DMZ] openrmm-gateway  ◄──── mTLS, opened from the LAN ──── [LAN] openrmm-core ──► PostgreSQL
                   terminates agent mTLS                                        enrollment, CA key
                   relays streams                                               openrmm-server, openrmm-signer
                   no DB credentials, no CA key
```

- `openrmm-core` (LAN) opens a long-lived mTLS tunnel **to** the gateway (port 8444); the firewall allows no connection from the DMZ to the LAN. On the tunnel the roles are reversed: the gateway is the gRPC client, the core the server. One tunnel at a time, reopened within seconds when it drops; keepalives detect dead tunnels.
- Tunnel authentication: the core presents a dedicated certificate (`openrmm://core`, issued by the agents CA, not usable as an agent identity) and pins the open-rmm root; the gateway accepts only core certificates on the tunnel port.
- The gateway terminates the agents' mTLS, checks client certificates against the agents CA certificate (public part only) and relays an **allow-list** of methods (enrollment, agent stream, renewal, module and release downloads) as **opaque frames**: it never decodes payloads, so new RPCs need no gateway change, and internal services are unreachable from the internet.
- The verified client chain and the agent's address travel as metadata built from scratch by the gateway (nothing sent by the agent is forwarded). The core honours that metadata **only on calls received through a tunnel** and **verifies the chain again** against the agents CA, then applies the usual checks (current certificate, not revoked).
- Certificate issuance, agent authorization, database access and job dispatch live in the core. Enrollment is rate-limited both at the gateway and in the core.
- A compromised gateway can delay or drop traffic and read what passes through it; it cannot forge jobs (signed), modules or releases (signed offline), issue certificates, reach the database, or claim an identity whose certificate it has never seen. 📋 Agent-signed messages and end-to-end encryption of results between agent and core would also close the impersonation-with-observed-certificate and read sides.
- Single-host deployments: core and gateway in the same Compose stack. Separate DMZ host: `deploy/dmz/compose.yaml` ([INSTALL.md](INSTALL.md)).

---

## 7. PowerShell commands (R9) ✅

- `script` module (capability `adhoc_script`): runs `params.script` and returns output, warnings and errors in order, terminating errors included.
- Every run needs per-command MFA; the full script text goes to the audit log.
- The script travels in the signed job (stdin), never on a command line; Script Block Logging, AMSI and Defender stay on.
- 📋 Script library with four-eyes publication; 📋 interactive remote shell with session recording.

---

## 8. Modules (plugins)

All modules are signed plugins outside the agent core, assigned by jobs or policies (§3.7).

### 8.1 `inventory` ✅

| Area | Data | Windows source |
|---|---|---|
| System | Manufacturer, model (Lenovo marketing name), SKU, serial, chassis, domain, virtual machine | `Win32_ComputerSystem(Product)`, `Win32_BIOS`, `Win32_SystemEnclosure` |
| OS | Edition, version, build with UBR, display version (24H2), **installation type (client/server)**, install date, last boot, logged-on user | `Win32_OperatingSystem`, registry |
| BIOS/UEFI | Vendor, version, date, UEFI/legacy, Secure Boot | `Win32_BIOS`, `Confirm-SecureBootUEFI` |
| CPU, memory | Model, cores, threads; memory per slot | `Win32_Processor`, `Win32_PhysicalMemory` |
| Disks, volumes | Model, serial, type, bus, **health**; volumes, free space, **BitLocker** state and method | `Get-PhysicalDisk`, `Win32_LogicalDisk`, `Win32_EncryptableVolume` |
| Network | Adapters, MAC, IP, gateway, DNS, DHCP | `Win32_NetworkAdapterConfiguration` |
| Monitors, battery, TPM | Monitor serials, **battery health** and cycles, TPM version | `WmiMonitorID`, battery WMI classes, `Win32_Tpm` |
| Software | `Uninstall` keys (64/32-bit HKLM and the loaded user hives), MSI product code, silent uninstall available; never `Win32_Product` | registry |
| **Remote-access tools** | **Supremo ID** (`HKLM\SOFTWARE\WOW6432Node\Supremo\ClientID`), AnyDesk ID (`%ProgramData%\AnyDesk*\system.conf`), TeamViewer ID (`ClientID`) | registry / config files |

- The module is read-only; each section is collected on its own, so a failing WMI class leaves only that section empty (with a warning in the job log).
- The Linux entrypoint collects a subset: system, OS, firmware, CPU, memory, disks, packages (dpkg/rpm).
- It runs through a policy (e.g. daily) or as a command. The console treats a result as an inventory only when its own records say it comes from `inventory`/`collect` (job or policy rule), never on the agent's word.
- The console decodes only known fields, clips strings and bounds lists, and stores the normalized document. It keeps the latest inventory per agent and a **change history** (software installed/removed/updated, memory, disks, disk health, BIOS, OS build, BitLocker state, remote-access ids), at most 2000 entries per agent.
- 📋 Later: MSIX packages, 2023 Secure Boot certificates and ESRT, disk wear, alerts on changes.

The installation type is also sent by the core on connect (one field), so the console splits **clients and servers** before any inventory runs.

### 8.2 `accesslog` — local and RDP logons ✅

- Collects events incrementally: the last record id of each event log is kept in the module's **state directory** (§3.4), so each run reads only new events; the first run reads the last 24 hours.
- Events: Security `4624` for logon types 2, 7, 10, 11 (machine and service accounts dropped), `4625` (all types, for failure and spraying detection), `4740`; RemoteConnectionManager `1149` (RDP authentication with source IP); LocalSessionManager `21`/`24`/`25`.
- Only normalized fields reach the console (time, kind, user, domain, logon type, source IP/host, status). They are kept **90 days** and shown on the agent page.
- **Unusual logons**, evaluated in the console on the events not seen before:
  - **RDP from an address outside the allowed subnets → critical alert**. The subnets are set per tenant in **Impostazioni** (Admin, audited); when none are set, the private ranges and loopback are allowed;
  - RDP from an allowed address never used before by that user on that endpoint → warning, after a 7-day learning period;
  - ≥ 10 failed logons from one source in one collection → warning; failures on ≥ 5 different users from one source → critical (password spraying);
  - account lockout → warning.
- 📋 Later: logons outside working hours, privileged logons (4672), operator-marked expected addresses.

### 8.3 Trend Micro and protection status ✅

| Plugin | Where | What |
|---|---|---|
| `trendmicro` (`status`) | Endpoints with a Trend agent | Products recognized by services and Uninstall entry: Standard Endpoint Protection (`ntrtscan`, `tmlisten`, `TMBMServer`, `TmCCSF`), Server & Workload Protection (`ds_agent`, `ds_notifier`, `AMSP`), Vision One Endpoint Basecamp (`EndpointBasecamp`), Zero Trust Secure Access. Version, service state; a check per product |
| `protection-status` (`status`) | Clients and servers | Antivirus registered in Windows Security Center (clients), Microsoft Defender when it is the active antivirus, Windows Firewall profiles |
| Vision One connector (console) | `openrmm-core`, EU region API (`api.eu.xdr.trendmicro.com`), read-only key | Each endpoint as seen from the cloud, Workbench alerts |

- The service names are the most common ones and **not yet verified on the customer's endpoints**; every definition (services, required services, Uninstall name pattern) can be overridden by the policy parameters, e.g. `{"expect":["sep"],"definitions":{"ztsa":{"services":["…"],"required":["…"]}}}`, without a new module version.
- Typical policy: rule `trendmicro`·`status` every 15 minutes with `when: {"service_exists":"ntrtscan"}` and params `{"expect":["sep"]}` for clients, `when: {"service_exists":"ds_agent"}` and `{"expect":["swp"]}` for servers. Endpoints without Trend never download the module.
- **Vision One connector:** every 15 minutes it lists the endpoint inventory and the Workbench alerts of the last period, and matches endpoints to agents by host name. It stores checks `visionone/protection` (agent status, version, last connection: an endpoint online for open-rmm but not connected to Vision One for 24 h fails), `visionone/sensor` and `visionone/registered` (a Windows agent online but missing from Vision One is a warning). Workbench alerts on a matched host become open-rmm alerts (high/critical → critical, medium → warning), raised once per Workbench id. Paging links are followed only on the API host, so the key is never sent elsewhere. 📋 API field names to verify against the live tenant.

### 8.4 Checks and alerts ✅

- **Checks convention:** any module may add `"checks": [{"id": "sep", "status": "ok|warning|failing", "summary": "…"}]` to its result. The console stores the latest status per agent as `<module>/<id>` (module from the console's own records) and shows them on the agent page and, as the worst status, in the agent lists. A check that starts failing raises an alert.
- **Alerts** have a severity (info, warning, critical), are merged while open (same key: count and last time) and are taken in charge by an Operator (audited). The number of open alerts is shown in the navigation.

### 8.5 `winupdate` ✅

- Windows Update Agent COM API. `scan`: missing updates (classification by category id, so it works on any display language; KB, severity, release date), pending reboot and since when, last successful installation, **who manages updates** (WSUS from the Group Policy keys, Intune from the MDM policy keys, or nobody). `install`: downloads and installs by classification (default security, critical, rollup, update, definition), with `include_kbs`/`exclude_kbs`; skips updates that need user input; **never reboots**.
- **WSUS/Intune coexistence:** on a managed endpoint open-rmm only **observes** (scan, dashboards); `install` refuses unless the policy sets `allow_managed`.
- Checks: `winupdate/updates` (failing when security/critical updates released more than `max_age_days`, default 30, are missing) and `winupdate/reboot` (warning when a reboot has been pending for 3 days).
- 📋 Later: error-code translation, `wu-repair`, drivers and firmware through Windows Update, rings and KB blocking at console level.

### 8.6 `winget` and third-party updates ✅ (first version)

- The module runs the App Installer `winget.exe` directly (it is not on the system account's PATH). `scan` lists the applications with an available upgrade; `upgrade` upgrades given ids, or all except `exclude`. Package ids are validated before being passed to winget.
- winget has no machine-readable output for upgrades: this first version parses its table by the column positions of the header (independent of the display language); rows with truncated ids are skipped and logged. 📋 Move to `Microsoft.WinGet.Client` / the COM API, which need extra components on the endpoint.
- Check `winget/thirdparty`: warning when upgrades are available.
- ✅ **Console-side catalog** (instead of winget or Chocolatey on servers): the operator adds winget package ids to the tenant's catalog; the console reads their manifests from the winget community repository and matches each application against every endpoint's software inventory (by MSI product code, then by display-name prefix, editable), so outdated software is detected also where winget is not available (Windows Server 2019, LTSC) and for software installed by hand. The installer is downloaded **by the console**, over HTTPS only, and accepted only if its SHA-256 matches the manifest; it then goes into the package library and is distributed like any package (§8.7). "Check new versions" refreshes the catalog on request. 📋 Scheduled refresh, per-user apps through the user helper, private REST source.

### 8.7 Software distribution and removal (`software`) ✅

- **Package library** (page *Software*): Admins upload an installer (MSI, Inno Setup, NSIS, WiX bundle, or any exe with its silent switches) or import one from the winget catalog. Files are stored outside the database by SHA-256 in a volume written by the web console and read by the core; the metadata (name, version, kind, switches, product code, origin, uploader) is per tenant and audited.
- **Distribution:** an Operator picks a package and the endpoints (those with an older version are preselected) and approves **once with MFA** for all of them (§6.3). Each job pins the package hash; the agent downloads it through the gateway (also through the DMZ relay), only while that job is pending, and verifies size and hash.
- The `software` module verifies the **Authenticode signature** (refused unless the package was explicitly marked "unsigned allowed"), installs silently (`msiexec /i … /qn /norestart /l*v`, or the installer's silent switches), translates the common Windows Installer exit codes and never reboots: a 3010/1641 result records a reboot need that the `reboot` module honours until the next boot.
- **Uninstall from the console:** from the software list of an endpoint, approved with per-command MFA. The module removes the application the right way for its type: `msiexec /x {ProductCode} /qn /norestart` for MSI products (also when only the `UninstallString` points to msiexec), the registered `QuietUninstallString`, or the `UninstallString` plus switches the operator gives explicitly; it never runs an interactive uninstaller, refuses per-user installations and the open-rmm agent, and checks afterwards that the application is gone.
- 📋 Later: uninstall for a group ("remove 7-Zip 9.20 everywhere"), reading MSI properties at upload, Authenticode check on the console, removal of unused files.

### 8.8 Firmware ✅

`firmware` uses the vendor tools, which know the right packages for each model: **Dell Command Update** (`dcu-cli`, report XML), **Lenovo System Update** (`tvsu /CM`, results exported to WMI) and **HP Image Assistant** (`/Operation:Analyze`, JSON report; business models, consumer models reported as not supported). Other vendors (Acer) are reported as not supported; Windows Update drivers remain with `winupdate`. The tools are distributed from the package library.

- `scan` runs from the baseline policy; reports go to the Patch dashboard (counts, BIOS pending) and to the agent's Patch tab, with checks.
- `install` needs an operator's MFA approval (or a signed policy rule), by type (firmware, driver, vendor applications); **BIOS only when explicitly included**, and only on mains power with at least 50% battery; BitLocker is suspended for one reboot before a BIOS update. Never reboots: the reboot is recorded for `reboot` (maintenance windows).
- 📋 To validate on real Dell, Lenovo and HP endpoints (DCU exit codes and report format, System Update WMI class, HPIA report fields and exit codes). Later: BIOS password support, check that the BitLocker recovery key is escrowed before a BIOS update.

### 8.9 `reboot` ✅

Modules never reboot by themselves; they report a pending reboot and the `reboot` module applies the reboot policy. **When** is decided by the policy rule's maintenance window (§3.7); the module decides **whether**:

- `only_if_pending` (default true) and `min_pending_hours`;
- `notice_minutes` (default 15): Windows shows the countdown and message to logged-on users; with nobody logged on the reboot happens after one minute;
- `skip_if_user`: never reboot while someone is logged on (e.g. RDS servers);
- `min_battery_percent` (default 30): a laptop on battery below this is skipped.

**Proposed defaults** (to adjust per customer; they are ordinary policies):

| | Install | Reboot |
|---|---|---|
| Clients | `winupdate`·`install` every 24 h, window Mon–Fri 10:00–16:00 | `reboot` every 1 h, window Mon–Fri 12:30–14:00 and 18:00–21:00, `min_pending_hours: 24`, `notice_minutes: 15` |
| Servers | `winupdate`·`install` weekly, window Sun 02:00–05:00 | `reboot` every 1 h, window Sun 02:00–06:00, `notice_minutes: 5` |

📋 Later: user deferrals and presentation mode through the user helper, pre/post scripts.

### 8.11 Interactive shell (`shell`) ✅

A PowerShell session (bash on Linux) on one endpoint, in a terminal in the browser.

- **One MFA approval per session**, not per command: the operator approves "shell on this agent for N minutes" (at most 60, default 30) with a fresh MFA sign-in bound to that request, like any job; the signer signs it. A conscious exception to per-command approval (decision of 2026-10-19), compensated by the limits below.
- **Opt-in on the endpoint**: the local policy `AllowInteractiveShell` (GPO, ADMX) is off by default; without it the agent rejects the job. Policies can never schedule a shell, it is not offered as a generic command or in bulk actions, and only the operator who approved a session can attach to it.
- **The agent runs a fixed shell** (Windows PowerShell by absolute path, or bash) on a **ConPTY** / Unix PTY inside a Job Object / process group, started with the signed module's startup script; it ends the session at the time limit, after 15 minutes without keystrokes, or when the operator closes it, killing the whole process tree.
- **Path**: agent → Shell stream (through the DMZ relay) → core, which checks that the stream belongs to an unfinished shell job of that agent → **shell broker** on a Unix socket shared only with the web console → WebSocket (same origin) → **xterm.js**, served by the console itself (`static/vendor/xterm`, MIT). The shell page alone allows scripts (`script-src 'self'`) and inline styles (needed by xterm.js).
- **Audit**: session attached and detached, and **every line typed** (`shell.input`, rebuilt from the keystrokes) in the console's audit log; the job result records duration, bytes and how the session ended. Output is not recorded.
- **Federation**: works from a central console too; the WebSocket is relayed over the link, the customer console audits the central operator.

### 8.10 Further proposed plugins 📋

| Priority | Plugin | Purpose |
|---|---|---|
| ✅ | `protection-status` | Windows Security Center: registered antivirus, firewall, Defender (covers non-Trend products) |
| High | `bitlocker` | Status per volume; recovery key escrowed in AD/Entra |
| High | `local-admins` | Members of the local Administrators group, alert on change |
| High | `disk-health` | Free space thresholds, disk errors, SMART |
| High | `critical-events` | Unexpected shutdowns (6008), bugchecks, disk errors, pending reboots |
| High | `security-baseline` | SMBv1, RDP without NLA, firewall off, autorun, Guest account, LLMNR/NetBIOS, TLS settings |
| Medium | `backup-status` | Veeam / Windows Server Backup last jobs (possible link with backup-console) |
| Medium | `cert-expiry` | Machine and IIS certificates about to expire |
| Medium | `persistence` | New scheduled tasks, services and autoruns |
| Medium | `service-watch` | Configurable critical services per server, optional restart |
| Console | Connectors | Vision One (EU), Dell/Lenovo warranty, Active Directory (computers without agent, stale objects) |

---

## 9. Multi-tenancy and federation

### 9.1 Tenants ✅

`tenant_id` in every table, API and job; isolation enforced by PostgreSQL row-level security; the console refuses to run as a superuser or `BYPASSRLS` role.

### 9.2 Federation ✅

A console can manage **local tenants** (its own agents) and **linked customer consoles**. Requirement R19: **every operation available on a customer console is available from the central console**. Guide: [FEDERATION.md](FEDERATION.md).

- **Same software, two roles.** The central console is an open-rmm console; federation is a link, not a different product. Two levels at most.
- **The customer console opens the link**: TLS 1.3 to the central console's link listener (`OPENRMM_FEDERATION_LISTEN`), outbound only, a few tunnels kept open. Both sides are self-signed and **pinned**: the central console's fingerprint is in the one-time link token (24 hours), the customer console's certificate is registered when it presents the token once.
- **One console, served over the link.** On the tunnels the roles are reversed: the central console is the HTTP client, the customer console serves its own web console. When an operator opens a linked console, the central console forwards each request with the operator's identity (object id, directory, roles, a per-session key); the customer console checks the directory against its trust settings, **caps the roles** to its maximum, keeps a separate session (and CSRF token) per central session, and renders its own pages with its own checks. Only redirects inside the console and a few response headers are relayed; the security headers are the central console's.
- **Commands stay signed where the agents are.** A step-up started on a linked console comes back to the central console, which signs the operator in again with MFA against its own directory, with the customer's nonce (the hash of the exact request), and hands the id_token over the link. The customer console verifies it and passes it to its signer, which accepts it only if the customer configured the central directory on the signer too (`OPENRMM_FEDERATION_*`, deployment configuration, not the web console). The central console never holds customer signing keys and cannot create commands or policies by itself.
- **Local control and audit.** Every action is in the customer's audit log as "operator … via central console" (sessions included). The customer chooses the highest role (Admin, Operator or Reader), and can suspend (tunnels closed at once), resume or remove the link; these settings are not reachable over the link. The central console can revoke a link.
- **Data:** only a summary is synchronized every 5 minutes for the central dashboard (agents, online, pending, open and critical alerts, missing security updates, pending reboots); pages are fetched live. The customer console stays fully autonomous when the link is down.

---

## 10. Packaging and installation ✅

- **MSI** built on Linux with msitools/wixl (LGPL): agent and watchdog in `Program Files\open-rmm\versions\<version>\`, two services, configuration from public properties (`SERVER`, `ENROLLTOKEN`, `ROOTCA`, `JOBSIGNINGKEYS`, `MODULESIGNINGKEYS`, `RELEASESIGNINGKEYS`, `ALLOWADHOCSCRIPTS`).
- With Group Policy the MSI is assigned unchanged and configured through the **ADMX** templates (`HKLM\SOFTWARE\Policies\open-rmm`, Italian and English).
- Services re-apply at every start what wixl cannot express: recovery actions, delayed start, scheduled check, registry and folder ACLs. Without a complete configuration they keep running and retry every minute. They are registered with an explicit `-service` flag.
- Removal deletes services, scheduled task, update-installed versions and agent state including its private key (not during upgrades).
- ✅ Authenticode signing of executables and MSI at build time (§12). 📋 Uninstall protection, Linux packages.

Details: [AGENT-INSTALL.md](AGENT-INSTALL.md).

---

## 11. Web console

Implemented ✅: agents (pending/active/revoked, approve, revoke), command and script execution with step-up, jobs with live refresh, modules, enrollment tokens, agent updates, audit log.

**Layout ✅ (inspired by Tactical RMM's console, no code reused):**

- left: tree of **sites** with an "all" node and "no site"; a site is a list of subnets, and an agent belongs to the first site containing one of its adapter addresses (from the inventory) or the address it last connected from. Sites are managed by Admins. ✅ Below the sites, the **Active Directory containers (OUs)** holding agents, when AD is integrated (§12); 📋 tenants when federated.
- top of the main area: tabs **All · Clients · Servers**, a search box (name, user, model, serial, remote-access id);
- agent table with status icons (online, alerts, failing checks, missing patches, pending reboot, outdated applications), site, logged-on user, model, OS, Supremo id, last contact; multi-select for **bulk actions**: a command or script on up to 500 agents with **one MFA approval** (one signed job per agent, only actions available on every selected platform), or a package deployment with the selection preselected;
- bottom panel for the selected agent, with tabs **Summary · Checks · Patches · Software · Inventory · Logons · Policies · History · Notes · Commands**; the full agent page stays available;
- **notes** per agent (author and date, audited);
- light and dark themes (automatic by default, kept in the session); still server-rendered with no JavaScript, under the same strict CSP.
- **Italian and English** ✅: a language selector at the top right of the header; the choice is kept in the session, and until the operator chooses, the browser's `Accept-Language` decides (Italian by default, also on the sign-in error pages). Italian is the source text: an English catalog keyed by the Italian strings covers templates, flash and error messages, status labels and date formats, and a test checks that every key has an English entry with the same format verbs.

Planned 📋:

- ✅ **Separate Clients and Servers sections**, by OS installation type, with search by name, user, model, serial and remote-access id. ✅ Filter by site and by OU. 📋 Different default policies.
- ✅ **Update dashboard (Patch):** endpoints ranked by an update score — missing security updates and their age in days and Patch Tuesdays, other updates, pending reboot and for how long, outdated third-party applications — with compliance, counters and the most widespread outdated applications ("Chrome outdated on 37 PCs"); filters Clients/Servers. 📋 Console-side catalog, compliance by site/OU.
- **Package library**, software distribution and **uninstall from the Software tab** (§8.7).
- **Policies** editor with per-version MFA approval (§3.7).
- ✅ Inventory on the agent page (hardware, BitLocker, battery, network, software, change history). 📋 Alerts, federation (tenant switcher across local and federated tenants).

---

## 12. First-time setup ✅

The bootstrap stays on the command line (`deploy/setup-pki.sh`, `deploy/setup-secrets.sh`, `openrmm-admin`): it creates the agents PKI, the signing keys and the Entra ID configuration before the console can start. Offline keys (root CA, module and release keys) are created on the operator's machine and never reach the server.

Once Entra ID sign-in works, the **Configurazione** page (Admin role) is a checklist computed from the console's state, each item with a link to where it is done:

- Entra ID sign-in with MFA;
- **sites** and their subnets (§11);
- **subnets RDP is allowed from** (§8);
- **modules** published, against the list of recommended ones;
- **baseline policy**: the policy editor prefilled with the published modules — inventory, Windows and winget scans, protection status, logons, Trend Micro where its services exist, Active Directory on domain controllers — approved with MFA like any policy;
- **agent distribution**: enrollment token, active and pending agents;
- **code signing**;
- **Active Directory** (optional).

### 12.1 Code signing (Authenticode) and agent installers

**Recommended: the `builder` service.** A separate container (`openrmm-builder`, Debian with msitools/wixl, osslsigncode and OpenSSL; no published port, reachable only by the web console through a Unix socket, outbound only to the timestamp server) holds the signing key **encrypted with a passphrase the console never stores** (PKCS#8, PBKDF2-SHA256 600,000 iterations, AES-256): OpenSSL and osslsigncode read it with the passphrase through a pipe, so the key is never written in clear. From the console (**Agent installation** page, Admin):

1. **Dedicated CA**: the console creates a code-signing CA (10 years, end-entity certificates only) and the signing certificate (3 years) with the subject given (organization, unit, locality, province, country); the CA key stays in the builder, encrypted, to renew the certificate from the console.
2. **Enterprise CA (AD CS)**: the key is created in the builder and never leaves it; the console offers the request (CSR) for the *Code Signing* template and imports the issued certificate, checking that it matches the key.
3. **Public certificate**: import of a PFX (OpenSSL output piped straight into the encrypted form).

**Signed installers preconfigured for this console**: an Admin approves a build with a fresh MFA sign-in (bound to the version), then enters the passphrase (never kept in the session). The builder signs both executables of the published release, builds the MSI with the gateway address, the root certificate, the three public keys and a **dedicated enrollment token** as property defaults (one year, 10,000 uses, **never auto-approving**: PCs appear pending approval), signs the MSI with an RFC 3161 timestamp and streams it back; the console keeps it in the package store and offers it for download (Operator role). Everything is audited. A double click installs the agent with nothing to enter; Group Policy values still take precedence. If an installer leaks, revoking its token is enough.

**Alternative without the builder**: keys created by `openrmm-admin codesign ca|csr` on a build machine, `make msi SIGN_CERT=… SIGN_KEY=…`, and only the public certificate pasted in the console.

Either way the console offers `codesign.cer` (Trusted Publishers) and, for a dedicated CA, `codesign-ca.cer` (Trusted Root) for Group Policy, and warns 60 days before expiry.

### 12.2 Active Directory (optional)

The `adinventory` module lists the computer objects of the domain through ADSI, with the **computer account** of the endpoint it runs on (SYSTEM): the console holds **no AD credentials** and needs no LDAPS access to the domain controllers. It runs from the baseline policy on the domain controllers (condition `service_exists: NTDS`) or on any member server.

The console matches computers and agents by host name and shows:

- **active computers without an agent** (enabled, logged on to the domain in the last 30 days) — usually the GPO did not apply;
- **stale objects** (enabled, no logon for over 90 days);
- Windows agents not found in the directory (workgroup, other domains);
- the **OU tree** of the agents in the agent list, and each agent's OU and domain logon in its summary.

📋 Later: policies applied by OU; a central console for federation (§9.2).

---

## 13. Roadmap

| Step | Content | Status |
|---|---|---|
| Phase 0 — foundations | PKI and enrollment, mTLS gateway, agent core, modules and SDKs, job queue, signer with per-command MFA, web console with Entra ID, watchdog and A/B updates, MSI and ADMX | ✅ (to be validated on real Windows) |
| 1 | DMZ / internal split (gateway as relay, `openrmm-core`) | ✅ |
| 2 | Policies with scheduling and conditional plugins | ✅ |
| 3 | `inventory` (incl. Supremo/AnyDesk/TeamViewer ids), OS installation type, Clients/Servers sections | ✅ |
| 4 | Security plugins: `trendmicro`, `protection-status`, `accesslog` with unusual-logon detection, checks and alerts, Vision One connector | ✅ (to be validated on real endpoints) |
| 5 | `winupdate`, `winget`, update dashboard, `reboot`, maintenance windows | ✅ (console-side catalog and user helper 📋) |
| 6 | Package library, winget catalog on the console, `software` (install/uninstall), multi-agent approval | ✅ |
| 7 | Console layout (site and OU tree, tabs, bottom panel, bulk actions, notes, themes); setup checklist, Authenticode signing, optional Active Directory | ✅ |
| 8 | Federation with full central operations | ✅ |
| 9 | `firmware`: BIOS, firmware and drivers through Dell Command Update, Lenovo System Update and HP Image Assistant, in the Patch dashboard | ✅ (to be validated on real endpoints) |
| 10 | Interactive shell: MFA per session, opt-in local policy, ConPTY, xterm.js, every line audited | ✅ (to be validated on real Windows) |
| 11 | Builder service: signing key on the console encrypted with a passphrase, dedicated CA or enterprise CA from the console, signed MSIs preconfigured with gateway, root certificate, keys and token | ✅ |
| Later | Further plugins (§8.10), Linux agent packages | 📋 |

---

## 14. Open questions

1. Exact service and registry names of Trend Micro Standard Endpoint Protection, Server & Workload Protection and ZTIA on the customer's endpoints.
2. Registry location of the Supremo ID (export from a PC with Supremo installed).
3. Does the customer have Entra ID P1 (Conditional Access authentication context for per-command MFA)?
4. Site LAN subnets allowed for RDP.
5. Default reboot policies for clients and servers (§8.9).
6. Hardware key (YubiKey/HSM) for the offline keys.

## 15. Decisions

| Date | Decision |
|---|---|
| 2026-10-16 | Project name **open-rmm**; licence AGPL-3.0 |
| 2026-10-16 | Agent and console in **Go**, database **PostgreSQL** |
| 2026-10-16 | Operators sign in **only with Microsoft 365 (Entra ID)**, **MFA mandatory**; on-prem AD not used for sign-in |
| 2026-10-16 | Ad-hoc PowerShell commands **on by default**, **MFA before every run** |
| 2026-10-16 | Console **hosted at the customer**, reachable from the internet; all connections start from endpoints |
| 2026-10-16 | WSUS and Intune supported in *observation* mode |
| 2026-10-16 | Configurable reboots per group |
| 2026-10-16 | The console refuses superuser / `BYPASSRLS` database roles |
| 2026-10-17 | Console in **Linux containers** (Docker Compose) |
| 2026-10-17 | New agents **pending approval** by default; auto-approval is a per-token option |
| 2026-10-17 | Automatic agent certificate renewal with a new key |
| 2026-10-17 | Modules as child processes with a JSON-lines protocol; jobs pin the manifest hash |
| 2026-10-17 | Server-rendered web console instead of React (no JavaScript dependencies, strict CSP) |
| 2026-10-17 | Job signing in `openrmm-signer`, only with a fresh, MFA, command-bound Entra id_token |
| 2026-10-17 | Agent updates: signed releases, side-by-side versions, watchdog switch and rollback, never downgrade, rings |
| 2026-10-17 | MSI built with msitools/wixl; Group Policy configuration through ADMX |
| 2026-10-19 | **Documentation, READMEs, project documents and commit messages in English** |
| 2026-10-19 | Trend Micro and logon monitoring are **plugins**; plugins are **activated by signed policies with declarative conditions** evaluated by the core |
| 2026-10-19 | Vision One tenant in the **EU (Germany)** region; console-side connector |
| 2026-10-19 | Clients run Standard Endpoint Protection, servers may run Server & Workload Protection; ZTIA = Zero Trust Internet Access |
| 2026-10-19 | RDP is expected **only from the LANs**: RDP from outside the allowed subnets is a high alert |
| 2026-10-19 | **Separate DMZ relay and internal core**; the internal side opens the connection |
| 2026-10-19 | **Federation with full operations from the central console**; commands signed by the customer's signer |
| 2026-10-19 | Separate Clients/Servers views; MSI software distribution; update dashboards with winget and console-side catalog; Supremo/AnyDesk/TeamViewer ids in inventory |
| 2026-10-19 | **Setup wizard**: code signing via enterprise CA, dedicated CA or public certificate; **optional** Active Directory integration |
| 2026-10-19 | DMZ split implemented: gateway relays opaque frames for an allow-list of methods; the core opens one mTLS tunnel and re-verifies forwarded identities |
| 2026-10-19 | Console layout inspired by Tactical RMM (tenant/site tree, Servers/Workstations/Mixed tabs, per-agent bottom panel); **software uninstall from the console** |
| 2026-10-19 | Third-party software on servers without winget: **no Chocolatey** for now (community scripts run as SYSTEM; it does not see software installed by hand); the console uses the **winget manifests** to detect outdated software from the inventory and distributes the installers itself, hash-checked, with manual approval |
| 2026-10-19 | Code-signing keys are created by `openrmm-admin` on the build machine, never by the internet-facing console, which keeps only the public certificate; the setup is a checklist page after the command-line bootstrap rather than a one-time-code wizard |
| 2026-10-19 | Active Directory is read by the `adinventory` module with a domain member's computer account instead of an LDAPS service account on the console |
| 2026-10-19 | Interactive shell approved with **MFA per session** (one agent, at most 60 minutes, every line audited, off unless the endpoint's local policy allows it) instead of per command; full terminal with xterm.js served by the console, scripts allowed on that page only |
| 2026-10-20 | The Authenticode key may live on the console, in a separate **builder** container, **encrypted with a passphrase** asked at each use (with MFA for builds); the console builds **signed MSIs preconfigured** with gateway, root certificate, public keys and a non-auto-approving enrollment token. Internal PCs reach the gateway in the DMZ through split DNS |
