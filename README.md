# open-rmm

Open-source Remote Monitoring and Management, designed with security as a primary requirement.

- **Agent** for Windows (clients and servers) and Linux, deployable through Group Policy, modular: new features arrive as signed plugins, without updating the agent.
- **Console** that can be hosted at the customer, multi-tenant, and federable under a central console.
- **Outbound-only connections** from the endpoints, mTLS with a pinned private CA, every command approved with a fresh MFA sign-in.

The project is at an early stage. The full design is in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Status

Phase 0 (foundations):

- [x] Agent ↔ console protocol (gRPC, [proto/openrmm/v1](proto/openrmm/v1))
- [x] PKI: offline root CA, agents CA, per-agent certificates carrying tenant and agent identity
- [x] Enrollment with tenant-bound, expiring, use-limited tokens (stored as hashes, rate-limited per IP)
- [x] mTLS gateway: without a valid certificate only enrollment is reachable
- [x] Agent: locally generated key, persistent connection, heartbeat, reconnection with backoff
- [x] Windows services with automatic restart; systemd units for Linux
- [x] Configuration from file, registry (MSI) and Group Policy (`HKLM\SOFTWARE\Policies\open-rmm`)
- [x] Signed jobs (Ed25519, validity window, addressee, persistent anti-replay)
- [x] PostgreSQL with per-tenant row-level security and an immutable hash-chained audit log
- [x] Approval of new agents, with optional automatic approval per token
- [x] Automatic agent certificate renewal with key rotation
- [x] Console in Linux containers (Docker Compose), unprivileged and read-only
- [x] Signed modules with PowerShell and sh SDKs; `sysinfo` and `script` modules
- [x] Job queue with immediate delivery and results that survive disconnections
- [x] Watchdog, scheduled health check, A/B automatic updates with rollback, rollout rings
- [x] Job signing service (`openrmm-signer`): signs only commands approved with a fresh MFA sign-in, verified independently
- [x] Web console with Entra ID sign-in and MFA: agents, approvals, commands and scripts, jobs, modules, tokens, updates, audit log
- [x] MSI for Group Policy (built on Linux with wixl) and ADMX templates (English, Italian)
- [x] DMZ split: internet-facing gateway as a relay without database or CA key; internal core opens the tunnel
- [x] Signed policies: periodic module actions with declarative conditions (conditional plugins), approved with MFA once per version
- [x] `inventory` module: hardware, BitLocker, battery, software, Supremo/AnyDesk/TeamViewer ids; change history; Clients and Servers sections
- [x] Security plugins: `trendmicro`, `protection-status`, `accesslog` with unusual-logon alerts (RDP outside the LAN subnets, password spraying, lockouts); checks and alerts; Trend Vision One connector (EU)
- [x] Updates: `winupdate` (WSUS/Intune observation mode), `winget`, `reboot`; maintenance windows in policies; Patch dashboard ranking endpoints by how far behind they are
- [x] Software: package library (upload or winget catalog, hash-checked), distribution to many endpoints with one MFA approval, silent uninstall from the console; outdated software detected from the inventory also without winget (Server 2019)
- [x] Console layout: site tree, Clients/Servers tabs, bottom panel per agent, bulk actions with one MFA approval, notes, light and dark themes, Italian and English (selector in the header)
- [x] Setup checklist with a baseline policy; Authenticode signing of executables and MSI (enterprise CA, dedicated CA or public certificate); optional Active Directory comparison (computers without agent, stale objects, OU tree) without AD credentials on the console
- [x] `firmware` module: BIOS, firmware and driver updates through Dell Command Update and Lenovo System Update, in the Patch dashboard, installed with MFA approval (BIOS only on request, BitLocker suspended for one reboot)
- [x] Interactive shell in the browser (xterm.js): one MFA approval per session, at most 60 minutes, only where the endpoint's Group Policy allows it, every line typed in the audit log; also from a central console
- [x] Federation: a central console operates linked customer consoles over an outbound, pinned link; commands still signed by the customer's signer with the central operator's MFA; role cap, suspend and audit at the customer
- [ ] Validation on real Windows

Next: validation on real Windows endpoints, Entra ID and Vision One. See the [roadmap](docs/ARCHITECTURE.md#13-roadmap).

## Documentation

- Server installation: [docs/INSTALL.md](docs/INSTALL.md)
- Microsoft Entra ID setup: [docs/ENTRA.md](docs/ENTRA.md)
- Agent installation on Windows (MSI, Group Policy): [docs/AGENT-INSTALL.md](docs/AGENT-INSTALL.md)
- Writing and publishing modules: [docs/MODULES.md](docs/MODULES.md)
- Agent updates: [docs/UPDATES.md](docs/UPDATES.md)
- Federation (central console for several customer consoles): [docs/FEDERATION.md](docs/FEDERATION.md)
- Development: [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)

```bash
make test
```

## Licence

open-rmm is distributed under the [GNU Affero General Public License v3.0](LICENSE). Anyone who modifies open-rmm and offers it as a network service must make the source code of their modifications available.
