# open-rmm — Architecture

> Status: draft v1.0 — 2026-10-19
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
| R6 | Windows Update: detection and installation | Module (§8.4) |
| R7 | Hardware and software inventory, logon events | Modules (§8.1, §8.2) |
| R8 | Third-party software and firmware updates | winget, vendor tools (§8.5, §8.7) |
| R9 | PowerShell commands from the console | `script` module ✅ (§7) |
| R10 | **Modular agent: new features never require an agent update** | Core principle (§3) ✅ |
| R11 | Automatic agent update | A/B with rollback (§5) ✅ |
| R12 | Operators sign in with Microsoft 365 (Entra ID); MFA mandatory | §6.6 ✅ |
| R13 | Console at the customer, reachable from the internet; **all connections start from the endpoints** | §4, §6.7 |
| R14 | Coexistence with WSUS and Intune | Observation mode (§8.4) |
| R15 | Configurable reboots per endpoint group | §8.8 |
| R16 | Separate client and server views, distinguished by OS | §11 |
| R17 | Software distribution by uploading an MSI | §8.6 |
| R18 | Dashboards of the endpoints that most need updates (Windows and third-party) | §11 |
| R19 | **Everything doable on a customer console is doable from the central console** | §9 |
| R20 | Guided first-time setup (web wizard), optional enterprise CA and Active Directory integration | §12 |

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
│ openrmm-gateway  (relay: no database credentials, no CA key) — target   │
└────────────────────────────────────▲───────────────────────────────────┘
                                     │ mTLS, opened from the LAN side
┌──────────────── LAN ───────────────┴───────────────────────────────────┐
│ openrmm-core  (agent sessions, enrollment, job dispatch) ──► PostgreSQL │
│ openrmm-server (web console)  ──► openrmm-signer (job signing key)      │
│ federation link ──(outbound, mTLS)──► central console (optional)        │
└────────────────────────────────────────────────────────────────────────┘
```

Today (✅) `openrmm-gateway` still contains what will become `openrmm-core` and talks to PostgreSQL directly; the split is the next step (🔜, §6.7).

### 2.1 Endpoint

| Component | Role | Expected update frequency |
|---|---|---|
| `openrmm-agent` ✅ | Core: transport, identity, signature checks, module cache and runner, job outbox, policy scheduler (🔜), health file | Rare (protocol or security fixes) |
| `openrmm-watchdog` ✅ | Restarts the agent when stopped or hung, applies staged updates with rollback | Very rare |
| `openrmm-userhelper` 📋 | Process in the user session: notifications, reboot prompts, modules in user context (per-user apps, per-user winget) | Rare |
| Modules ✅ | Every feature | Often, **without touching the agent** |

### 2.2 Console

| Component | Technology |
|---|---|
| `openrmm-gateway` ✅ | Go, gRPC; agents endpoint (§4) |
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
/console/cmd           openrmm-gateway, openrmm-server, openrmm-signer, openrmm-admin
/internal
  /pki /signing /tlsconf /ids /release /modules   shared crypto, identity, release and module formats
  /agent/...           agent core: config, identity, client, jobs, executor, runner, modcache,
                       updater, watchdog, svcctl, winsvc, health, secfile, hostinfo
  /console/...         gateway, store, audit, authn, jobreq, signer, web
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
- 🔜 **policy scheduler with declarative conditions** (§3.7);
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

The core starts the module in a temporary working directory with a minimal environment and writes one JSON request line on stdin. The module writes JSON lines on stdout — `progress`, `log` and exactly one final `result` or `error`. Size limits and timeouts are enforced; on violation the core kills the whole process tree (process group on Linux, Job Object on Windows). The SDKs hide the protocol.

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

### 3.7 Policies and conditional plugins 🔜

Recurring work (inventory every 24 h, Trend Micro status every 15 min, logon events every 5 min) and automatic plugin activation are expressed as **policies**:

```yaml
policy: security-baseline          # assigned to a group (clients, servers, a site, an OU)
version: 7
rules:
  - module: trendmicro-endpoint@1.0.0   # pinned by manifest hash
    action: status
    every: 15m
    when: { service_exists: "ds_agent" }   # Server & Workload Protection
  - module: trendmicro-endpoint@1.0.0
    action: status
    every: 15m
    when: { service_exists: "TMBMServer" } # Standard Endpoint Protection (exact names to verify)
  - module: accesslog@1.0.0
    action: collect
    every: 5m
```

- A policy is **signed by the signer** after an operator approves it with MFA — once per policy version, not at every run.
- The core evaluates only **declarative conditions**: service exists, file exists, registry key or value exists, OS family (client/server). No product-specific logic enters the core.
- The module is downloaded only when a rule applies: endpoints without Trend Micro never receive the Trend module. This is how "agent detects Trend Micro → downloads and enables the plugin" works without enlarging the core.
- Policies are stored locally and keep running offline; results are queued.
- Modules with the `adhoc_script` capability are not allowed in policies.

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
| Compromised DMZ host | 🔜 the DMZ relay holds no database credentials and no CA key; the LAN side opens the connection (§6.7) |
| Rogue agent enrollment | Tenant-bound, expiring, use-limited tokens; new agents pending approval |
| Man-in-the-middle | mTLS, pinned private root CA |
| Local tampering with the agent | Restricted ACLs on files, registry and pipes; module cache re-verified before each run; 📋 Authenticode-signed binaries |
| Tampered module, package or release | Ed25519 signatures and SHA-256 checked **before** anything runs |
| Job replay | Nonce, expiry and agent id in the signed payload; persistent replay cache |
| Operator abuse | Roles, per-job MFA, immutable hash-chained audit log; 📋 four-eyes approval for mass actions |
| Supply chain | Few dependencies, `govulncheck`, `gosec`, `staticcheck` in CI; 📋 SBOM, reproducible builds |

### 6.2 Keys

| Key | Where | Signs |
|---|---|---|
| Root CA | Offline | Agents CA |
| Agents CA | Console (🔜 internal core only) | Agent and gateway certificates |
| Module release | Offline | Module manifests |
| Agent release | Offline | Agent releases |
| Job signing | `openrmm-signer` only (📋 HSM) | Jobs and policies |
| Code signing (Authenticode) | Enterprise CA, dedicated CA or public CA (§12) | Windows executables and MSI |

### 6.3 Job signing ✅

The signer signs a job only if the request carries an id_token issued by Entra ID **for that exact request** (the OIDC `nonce` is the canonical hash of agent, module, manifest hash, action, parameters and validity), recent, with MFA, by an operator with the Operator or Admin role for that tenant, and never used before. The signer verifies all of this itself, with Microsoft's public keys; it does not trust the console.

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

### 6.7 Exposure: DMZ and internal network 🔜

Only the agents endpoint is meant for the internet; the web console stays on the operators' LAN/VPN (📋 or behind Entra Application Proxy).

**Target layout (next step):**

```
internet ──► [DMZ] openrmm-gateway  ◄──── mTLS, opened from the LAN ──── [LAN] openrmm-core ──► PostgreSQL
                   terminates agent mTLS                                        enrollment, CA key
                   relays streams                                               openrmm-server, openrmm-signer
                   no DB credentials, no CA key
```

- `openrmm-core` (LAN) opens a long-lived mTLS connection **to** the gateway; the firewall allows no connection from the DMZ to the LAN.
- The gateway terminates the agents' mTLS, checks client certificates against the agents CA certificate (public part only) and relays streams, enrollment requests (CSR) and downloads to the core.
- Certificate issuance, agent authorization (revocation, approval), database access and job dispatch live in the core.
- A compromised gateway can delay or drop traffic and read what passes through it; it cannot forge jobs (signed), modules or releases (signed offline), issue certificates or reach the database. 📋 End-to-end encryption of job results between agent and core would also close the read side.
- Single-host deployments keep working: core and gateway in the same Compose stack.

---

## 7. PowerShell commands (R9) ✅

- `script` module (capability `adhoc_script`): runs `params.script` and returns output, warnings and errors in order, terminating errors included.
- Every run needs per-command MFA; the full script text goes to the audit log.
- The script travels in the signed job (stdin), never on a command line; Script Block Logging, AMSI and Defender stay on.
- 📋 Script library with four-eyes publication; 📋 interactive remote shell with session recording.

---

## 8. Modules (plugins)

All modules are signed plugins outside the agent core, assigned by jobs or policies (§3.7).

### 8.1 `inventory` 📋 (next after policies)

| Area | Data | Windows source |
|---|---|---|
| System | Manufacturer, model, SKU, serial, chassis, hypervisor | `Win32_ComputerSystem(Product)`, `Win32_SystemEnclosure` |
| OS | Edition, version/build, **installation type (client/server/core)**, install date, activation, last boot | `Win32_OperatingSystem`, registry |
| BIOS/UEFI | Version, date, UEFI/legacy, Secure Boot, **2023 Secure Boot certificates**, ESRT | `Win32_BIOS`, registry |
| CPU, memory | Model, cores; memory per slot | `Win32_Processor`, `Win32_PhysicalMemory` |
| Disks, volumes | Model, serial, type, **health**, wear; volumes, free space, **BitLocker** | `MSFT_PhysicalDisk`, `Win32_EncryptableVolume` |
| Network | Adapters, MAC, IP, gateway, DNS | `MSFT_NetAdapter` |
| Monitors, battery, TPM | Monitor serials, **battery health**, TPM version | `WmiMonitorID`, battery WMI, `Win32_Tpm` |
| Software | `Uninstall` keys (32/64-bit, HKLM and every HKCU), MSIX; never `Win32_Product` | registry |
| **Remote-access tools** | **Supremo ID**, AnyDesk ID, TeamViewer ID | registry / config files (exact Supremo location to be verified) |

Sent in full at enrollment, then daily as differences; the console keeps the change history (RAM removed, disk degrading) and raises alerts.

The installation type is also sent by the core on connect (one field), so the console can split **clients and servers** before any inventory runs.

### 8.2 `accesslog` — local and RDP logons 📋

- Collects normalized events incrementally (bookmark, no duplicates): `4624` by logon type (2, 7, 10, 11; 3 filtered), `4625`, `4634`/`4647`, `4672`, `4740`, RDP `1149` (with source IP) and `21`/`24`/`25`.
- Only normalized events reach the console (volume, GDPR).
- **Unusual logons**, evaluated in the console:
  - **RDP from an address outside the site's allowed LAN subnets → high alert** (RDP is expected only from the LANs);
  - RDP from an internal address never seen for that user/server → warning;
  - logons outside usual hours, privileged logons, repeated failures (also spread across users: password spraying);
  - a learning period and operator-marked "expected" addresses limit noise.

### 8.3 Trend Micro 📋

| Plugin | Where | Checks |
|---|---|---|
| `trendmicro-endpoint` | Clients (Standard Endpoint Protection), servers (Server & Workload Protection) | Product detected, version, services running, connection to Vision One, pattern and engine dates, real-time protection |
| `trendmicro-ztia` | Where the Zero Trust Internet Access client is installed | Installed, version, service running, connected |
| Vision One connector (console) | EU region API (`api.eu.xdr.trendmicro.com`), read-only key | The same endpoint as seen from the cloud; mismatches become alerts (e.g. PC online, agent disconnected in Vision One) |

Plugins are activated by policy conditions (§3.7). Service and registry names will be confirmed on real endpoints.

### 8.4 `winupdate` 📋

WUA COM API (`scan`, `download`, `install`, `history`); categories and rings, KB blocking, maintenance windows; WSUS/Intune detection with **managed** and **observation** modes; error-code translation and a separate `wu-repair` module.

### 8.5 `winget` and third-party updates 📋

- On clients: `Microsoft.WinGet.Client` / COM API (never parsing text output); approved package list; rings; pinning; per-user apps through the user helper; `bootstrap` installs App Installer where missing.
- **Console-side catalog:** the console imports the winget community index and matches it against each endpoint's software inventory, so outdated software is detected also where winget is not available (Windows Server 2019, LTSC). This drives the update dashboards (§11).
- 📋 Private REST source for internal packages.

### 8.6 Software distribution (`msi-install`) 📋

- Operators upload an MSI to the console's **package library**: the console stores it (file system / object storage, not the database), computes its SHA-256, reads ProductName/Version/ProductCode and checks its Authenticode signature (warning if unsigned).
- Deployment to PCs or groups is a normal job, approved with per-command MFA; the signed job pins the package hash.
- The generic `msi-install` module downloads the package over the agent connection, verifies the hash and runs `msiexec /i … /qn /norestart /l*v`; reboots go through the reboot policy. Uninstall by ProductCode. The same flow covers winget packages.

### 8.7 Firmware 📋

`firmware-dell` (Dell Command | Update), `firmware-lenovo` (Thin Installer), Windows Update firmware for other brands. Preconditions: AC power, battery level, **BitLocker recovery key escrowed**, BitLocker suspended for one reboot. Never automatic by default.

### 8.8 `reboot` 📋

Modules never reboot by themselves; they report "reboot required" and the `reboot` module applies the group's reboot policy (never / notify with deferrals / maintenance window only / immediate with notice), quiet hours, presentation mode, battery threshold, pre/post scripts.

### 8.9 Further proposed plugins 📋

| Priority | Plugin | Purpose |
|---|---|---|
| High | `protection-status` | Windows Security Center: registered antivirus, firewall, Defender (covers non-Trend products) |
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

### 9.2 Federation 📋

A console can manage **local tenants** (its own agents) and **federated tenants** (customer consoles linked to it). Requirement R19: **every operation available on a customer console is available from the central console** — agents, approvals, commands and scripts, policies, software distribution, updates and release targets, tokens, inventory, dashboards and audit.

- **Same software, two roles.** The central console is an open-rmm console; federation is a link, not a different product.
- **The customer console opens the link** (outbound mTLS to the central console), enrolled with a federation token. No inbound port at the customer.
- **One API, two backends.** The web console works against a tenant backend interface: local tenants read the local database, federated tenants call the customer console through the link. Pages and features are the same.
- **Commands stay signed where the agents are.** Agents trust only their own console's job key. A command from the central console is signed by the **customer's signer**, which accepts id_tokens of the central operators' directory (configured trust: issuer, client id, roles) with the same rules — fresh, MFA, bound to the exact command, single use. The central console never holds customer signing keys.
- **Local control and audit.** Every federated action is in the customer's audit log with the central operator's identity; the customer can suspend the link at any time (kill switch). Read-only or partial delegation remain possible settings, but full delegation is the default.
- **Data:** summaries synchronized for central dashboards; details fetched live through the link. The customer console stays fully autonomous if the link is down.
- Two levels at most (central → customer consoles). Versioned federation API.

---

## 10. Packaging and installation ✅

- **MSI** built on Linux with msitools/wixl (LGPL): agent and watchdog in `Program Files\open-rmm\versions\<version>\`, two services, configuration from public properties (`SERVER`, `ENROLLTOKEN`, `ROOTCA`, `JOBSIGNINGKEYS`, `MODULESIGNINGKEYS`, `RELEASESIGNINGKEYS`, `ALLOWADHOCSCRIPTS`).
- With Group Policy the MSI is assigned unchanged and configured through the **ADMX** templates (`HKLM\SOFTWARE\Policies\open-rmm`, Italian and English).
- Services re-apply at every start what wixl cannot express: recovery actions, delayed start, scheduled check, registry and folder ACLs. Without a complete configuration they keep running and retry every minute. They are registered with an explicit `-service` flag.
- Removal deletes services, scheduled task, update-installed versions and agent state including its private key (not during upgrades).
- 📋 Authenticode signing of executables and MSI (§12), uninstall protection, Linux packages.

Details: [AGENT-INSTALL.md](AGENT-INSTALL.md).

---

## 11. Web console

Implemented ✅: agents (pending/active/revoked, approve, revoke), command and script execution with step-up, jobs with live refresh, modules, enrollment tokens, agent updates, audit log.

Planned 📋:

- **Separate Clients and Servers sections**, by OS installation type; filters by site and OU; different default policies.
- **Update dashboards:** endpoints ranked by an update score — missing Windows updates and their age relative to Patch Tuesday, outdated third-party software (winget and console-side catalog), pending reboots; most-outdated applications ("Chrome outdated on 37 PCs"); compliance by site/OU.
- **Package library** and software distribution (§8.6).
- **Policies** editor with per-version MFA approval (§3.7).
- Inventory views, alerts, federation (tenant switcher across local and federated tenants).

---

## 12. First-time setup wizard 📋

A web wizard runs on the first start of the console, protected by a one-time code printed in the container logs, and disables itself when done. It covers:

- **Agents PKI** (root CA, agents CA, gateway certificate). Offline keys created by the wizard are offered for download **once** and then deleted from the server, with a clear warning; keys can also be generated on the offline machine and only their public part uploaded.
- **Code signing (Authenticode)**, selectable:
  1. **enterprise CA (AD CS):** the wizard generates a CSR, the operator gets it signed by the domain CA and uploads the certificate;
  2. **dedicated CA:** the wizard creates a small code-signing CA and certificate, and provides the certificate to distribute by GPO (Trusted Publishers, Trusted Root);
  3. **public certificate:** upload of a purchased certificate, or Microsoft Trusted Signing.
- **Entra ID** settings and first tenant, first enrollment token.
- **Active Directory integration (optional):** read-only LDAPS service account, used to compare domain computers with agents (computers without agent, stale objects) and to group endpoints by OU. Operator sign-in stays on Entra ID.
- **Federation (optional):** link to a central console.

---

## 13. Roadmap

| Step | Content | Status |
|---|---|---|
| Phase 0 — foundations | PKI and enrollment, mTLS gateway, agent core, modules and SDKs, job queue, signer with per-command MFA, web console with Entra ID, watchdog and A/B updates, MSI and ADMX | ✅ (to be validated on real Windows) |
| 1 | DMZ / internal split (gateway as relay, `openrmm-core`) | 🔜 |
| 2 | Policies with scheduling and conditional plugins | 📋 |
| 3 | `inventory` (incl. Supremo/AnyDesk/TeamViewer ids), OS installation type, Clients/Servers sections | 📋 |
| 4 | Security plugins: `trendmicro-endpoint`, `trendmicro-ztia`, Vision One connector, `accesslog` with unusual-logon detection, `protection-status` | 📋 |
| 5 | `winupdate`, `winget`, console-side catalog, update dashboards, `reboot`, user helper | 📋 |
| 6 | Package library and `msi-install`; setup wizard with code signing and optional AD | 📋 |
| 7 | Federation with full central operations | 📋 |
| Later | Firmware, further plugins (§8.9), Linux agent packages, interactive shell | 📋 |

---

## 14. Open questions

1. Exact service and registry names of Trend Micro Standard Endpoint Protection, Server & Workload Protection and ZTIA on the customer's endpoints.
2. Registry location of the Supremo ID (export from a PC with Supremo installed).
3. Does the customer have Entra ID P1 (Conditional Access authentication context for per-command MFA)?
4. Site LAN subnets allowed for RDP.
5. Default reboot policies for clients and servers (§8.8).
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
