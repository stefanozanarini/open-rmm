# Modules

Every Tempra RMM feature is a module (plugin): the agent only downloads, verifies and runs them. A new feature is added by publishing a module, **without updating the agent**.

## Chain of trust

```
module release key (console builder, or offline)
  └── signs the manifest
        ├── SHA-256 of the archive
        └── SHA-256 and size of every file
job signing key
  └── signs the job
        └── SHA-256 of the signed manifest  →  exact module version
```

Before every run the agent checks:

1. the job signature, that the job is addressed to it, its validity window, and that it was not received before;
2. the manifest signature, with a module release key configured on the endpoint;
3. that the manifest hash is the one pinned by the job;
4. archive and extracted files: hashes and sizes, no extra files, no dangerous paths;
5. the hashes of the cached files again, right before starting;
6. local policy: for example a module with the `adhoc_script` capability is refused when `AllowAdHocScripts` is 0.

The module key is held by the console's `builder` service, encrypted with the signing passphrase, or kept offline. Either way the web console and the gateway never hold it in clear: a module is signed only after an administrator's MFA approval and the passphrase, and the agents verify the signature themselves.

## Module layout

```
modules/sysinfo/
  manifest.json
  Main.ps1        Windows entrypoint (PowerShell)
  main.sh         Linux entrypoint (sh)
```

The SDK is added automatically under `_sdk/` when signing (`OpenRmm.psm1` for PowerShell, `openrmm.sh` for sh).

### manifest.json

```json
{
  "id": "sysinfo",
  "version": "1.0.0",
  "description": "Basic host information",
  "protocol_version": 1,
  "entrypoints": {
    "windows/amd64": { "type": "powershell", "path": "Main.ps1" },
    "linux/amd64":   { "type": "sh",         "path": "main.sh" }
  },
  "actions": {
    "info": { "description": "Hostname, OS, uptime", "timeout_seconds": 120 }
  },
  "capabilities": []
}
```

| Field | Notes |
|---|---|
| `id` | lowercase letters, digits and dashes, 2-41 characters |
| `version` | `x.y.z`. A published version is immutable: publish a new one |
| `entrypoints` | per `GOOS/GOARCH` platform. Types: `powershell` (Windows PowerShell 5.1, or `pwsh` on Linux), `binary` (executable), `sh` (Linux) |
| `actions` | `timeout_seconds` (default 600, max 14400). `context: "user"` is reserved for user-session execution, not available yet |
| `capabilities` | `adhoc_script` for modules that run code received in the job |

## Protocol (version 1)

The agent starts the entrypoint in a temporary working directory with a minimal environment: the service's environment variables are not passed, except a few essential system ones. It writes **one JSON line** on stdin:

```json
{"protocol_version":1,"job_id":"…","action":"info","params":{…},"tenant_id":"…","agent_id":"…","work_dir":"…","state_dir":"…"}
```

When the job carries packages, `packages` lists them (`file_name`, `path`, `sha256`): the agent has already downloaded them into `work_dir/packages/` and verified their size and hash.

`work_dir` is deleted after the run. `state_dir` (also `OPENRMM_STATE_DIR`) is private to the module and kept between runs, for example to remember the last event read; runs of the same module never overlap. Write state files atomically (temporary file, then rename).

The module writes JSON lines on stdout:

| Event | Example |
|---|---|
| progress | `{"type":"progress","percent":40,"message":"reading disks"}` |
| log | `{"type":"log","level":"warn","message":"…"}` |
| result (final) | `{"type":"result","data":{…}}` |
| error (final) | `{"type":"error","message":"…"}` |

There must be exactly one final event.

### Checks

A result may include checks, which the console shows on the agent page and in the agent lists, and which raise an alert when they start failing:

```json
{"type":"result","data":{"…":"…","checks":[{"id":"sep","status":"failing","summary":"servizio tmlisten Stopped"}]}}
```

`id`: lowercase letters, digits, `.`, `_`, `-` (up to 41 characters); the console stores it as `<module>/<id>`. `status`: `ok`, `warning` or `failing`. At most 50 checks per result. Lines that are not events are recorded as logs, so stray output (common in PowerShell) does not break the protocol. Limits: line 1 MB, total output 16 MB, result 3 MB, stderr kept 64 KB. If a module exceeds them, breaks the protocol or runs past its timeout, the agent kills it and all its child processes (process group on Linux, Job Object on Windows).

## Writing a PowerShell module

```powershell
Import-Module (Join-Path $PSScriptRoot '_sdk/OpenRmm.psm1')

Invoke-RmmModule @{
    info = {
        param($Params, $Request)
        Send-RmmProgress 50 'reading the operating system'
        $os = Get-CimInstance Win32_OperatingSystem
        @{ os = $os.Caption; build = $os.BuildNumber }   # the returned value is the result
    }
}
```

SDK functions: `Invoke-RmmModule`, `Send-RmmProgress`, `Send-RmmLog`, `Send-RmmResult`, `Send-RmmError`, `Read-RmmRequest`. An exception in the block becomes an error event with its position in the code. The SDK works on Windows PowerShell 5.1 and PowerShell 7 and uses explicit UTF-8 streams, so it also works without a console (as when started by the service).

## Action parameters (params.json)

A module may describe its actions' parameters in `params.json`, next to `manifest.json`. The console turns it into form fields (agent page and selections) and builds the job parameters from them, refusing values outside the description. It is not signed and not sent to agents (it stays out of the archive): what an agent runs is still decided by the parameters in the signed job. Without it the console shows a JSON field.

```json
{ "install": [
    { "name": "classifications", "type": "multi", "label": {"it": "Classificazioni", "en": "Classifications"},
      "options": [ {"value": "security", "label": {"it": "Sicurezza", "en": "Security"}} ], "default": ["security"] },
    { "name": "notice_minutes", "type": "int", "label": {"en": "Notice (minutes)"}, "min": 0, "max": 240, "default": 15 } ] }
```

Types: `string`, `text`, `int` (`min`, `max`), `bool`, `enum` and `multi` (`options`), `list` (one value per line). `required`, `help` and `default` are optional; an empty optional field is left out, so the module applies its own default.

## Signing and publishing

**From the console** (recommended). Once, a console administrator creates the module and release keys on the **Installer** page (*Module and release keys*), with the passphrase of the code-signing key: installers include the public keys from then on. Then, to publish:

1. **Moduli → Pubblica un modulo**, sign in again with MFA;
2. the modules shipped with the console (the repository's `modules/`, in the image) that are not published yet are listed, all selected: untick the ones you do not want, enter the passphrase.

A module of your own is published the same way from a zip of its folder (the one with `manifest.json`; the SDK is added automatically).

The console packs the module, the builder signs the manifest, and the console verifies the signature with the keys the agents trust before publishing it. Each version is published once: raise `version` in the manifest for a new one.

**Offline** (key kept on a separate machine). Sign on the offline machine that holds the module release key:

```bash
# once: the module release key (keep it offline)
openrmm-admin signing keygen -out module-release.key

openrmm-admin module sign -dir modules/sysinfo -key module-release.key
# → sysinfo-1.0.0.ormm
```

Then, on the console server:

```bash
export OPENRMM_MODULE_KEYS='ed25519:…'      # accepted public release keys
docker compose run --rm --user "$(id -u):$(id -g)" -v "$PWD:/in:ro" -e OPENRMM_MODULE_KEYS admin module publish -file /in/sysinfo-1.0.0.ormm
docker compose run --rm admin module list
```

`--user` lets the container read local files, whose permissions are restricted to your user. The console verifies signature and extraction before publishing, so a broken package never reaches the endpoints.

## Running a job

From the web console: agent page → **Esegui un comando**, or the **Script PowerShell** form for `adhoc_script` modules. After clicking, the operator is sent back to Microsoft for a new sign-in. `openrmm-signer` signs the command only if that sign-in:

- is recent;
- used MFA;
- was made by an operator with the right role;
- was issued for exactly that command.

Details in [ENTRA.md](ENTRA.md). The full text of scripts goes to the audit log.

### From the command line (development only)

`openrmm-admin job run -key <key>` signs directly with a job signing key, without MFA. It exists for development and tests and must not be used in production: the production key lives only in the `signer` container.

## Included modules

| Module | Platforms | Actions |
|---|---|---|
| `sysinfo` 1.0.0 | Windows, Linux | `info`: hostname, operating system, uptime |
| `inventory` 1.3.1 | Windows, Linux | `collect`: hardware, OS, BitLocker, battery, network, installed software, Supremo/AnyDesk/TeamViewer ids, local administrators, Chrome and Edge updates downloaded and waiting for the browser restart (`new_chrome.exe`, `new_msedge.exe`; the CVE page marks those computers). On a laptop, the check `inventory/battery`: wear, not charge level (full charge capacity against design capacity) — warning under 80%, failing under 60%; absent on a desktop. On a **domain controller** also the members of the domain's built-in privileged groups (Administrators, Account, Server, Print and Backup Operators) with the check `inventory/privileged-groups`: failing when Administrators holds anyone other than Administrator, Domain Admins and Enterprise Admins, or an Operators group is not empty. Results become the agent's inventory in the console |
| `accesslog` 1.0.0 | Windows | `collect`: new logon events since the previous run (local, RDP, failures, lockouts). The console stores them and raises alerts for unusual logons |
| `trendmicro` 1.1.1 | Windows | `status`: Trend Micro products installed, versions, services; one check per product (ZTSA problems are warnings, the others failures; `severity` per definition). Service names seen on Vision One 2026 agents: Endpoint Basecamp `Trend Micro Endpoint Basecamp`, ZTSA 2.40 `SWGMonitorService`; a required entry may list alternatives (`A|B`). Parameters: `expect`, `products`, `definitions` (override service names) |
| `protection-status` 1.0.0 | Windows | `status`: antivirus in Windows Security Center, Defender, firewall; checks `antivirus`, `defender`, `firewall` |
| `winupdate` 1.4.0 | Windows | `scan`: missing updates, pending reboot, WSUS/Intune management, installation history, **settings that block updates** (pinned `TargetReleaseVersion`, also left over in `UpdatePolicy\PolicyState`; Windows Update access off by policy, `NoWindowsUpdate` or Internet Communication Management; WSUS unreachable, not answering (`/ClientWebService/client.asmx`), `UseWUServer` without `WUServer`, no successful search for 14 days or no installation for 60; update servers redirected in `hosts`; pauses and deferrals; disabled services; low disk space) with the check `winupdate/policy`; `install`: by classification or KB, never reboots, refuses on managed endpoints unless `allow_managed`, attaches a short diagnosis when updates fail; `logs` (`days`, `windowsupdate_log`): Windows Update and servicing events, CBS.log errors, optionally WindowsUpdate.log, services, free space, pending operations, failed installations; `repair` (`source`, `sfc`, `reset_components`): `DISM /RestoreHealth` (from a same-build source when given), then `sfc /scannow`, optionally renaming `SoftwareDistribution` and `catroot2` first; fixes 0x800f0983 and 0x80073712, then restart and install again; `cleanup` (`download_cache`, `cleanmgr`, `component_cleanup`, `reset_base`, `previous_installations`): frees space on the system drive by emptying `SoftwareDistribution\Download` (and the `.old-*` folders of a previous reset), running Disk Cleanup (`cleanmgr /sagerun` on update cleanup, temporary, setup and error-report files; never the recycle bin, Downloads or driver packages; `Windows.old` only with `previous_installations`) and `DISM /StartComponentCleanup` (`/ResetBase` optional); reports the space freed per step and, when under 10 GB free remain, what takes the space (profiles, recycle bin, hibernation and paging files). The console offers it as "Libera spazio…" next to a low-disk blocker and on its alert |
| `osupdate` 1.1.0 | Linux | Operating system updates with the package manager of the distribution: `apt` (Debian, Ubuntu; security = from a `*-security` archive), `dnf`/`yum` (RHEL, Rocky, Alma, CentOS; security = `updateinfo` advisories, with severity), `zypper` (SUSE; security = patches of category security). `scan` refreshes the package lists and reports in the `winupdate` format (`manager`, updates with installed and new version, pending reboot), so the console shows Linux and Windows alike; each security update lists the CVEs it fixes (`dnf updateinfo --with-cve`, `zypper list-patches --cve`, for apt the changelog of the new version); `install`: `{"security_only": false, "packages": []}` (no packages: all), never reboots. Runs as root |
| `winget` 1.2.0 | Windows | `scan`: applications with an available upgrade; `upgrade`: `{"ids":[…]}` or `{"all":true,"exclude":[…]}`; `install`: `{"ids":["Google.Chrome"]}` for every user (machine scope), upgrading an installed copy. winget runs as the system account and does not see applications installed in a user's profile: the CVE page offers `install` only for Chrome, whose machine-wide install replaces the profile copy and keeps its data; for Firefox and Thunderbird it explains why not (both copies would stay and Firefox would open a new, empty profile) |
| `reboot` 1.1.0 | Windows, Linux | `reboot`: only if pending, with notice to logged-on users, skipped on low battery; use it in a policy with a maintenance window. On Linux the pending reboot comes from `/run/reboot-required`, `needs-restarting -r`, `zypper needs-rebooting` or a newer kernel installed, and `shutdown -r +N` warns the logged-on users |
| `software` 1.0.0 | Windows | `install`: the package of the job (MSI, Inno, NSIS, burn, exe with silent switches), Authenticode check; `uninstall`: `{"product_code":"{…}"}` or `{"name":"…","version":"…"}`, silent only. Used by the *Software* page and the uninstall buttons |
| `script` 1.0.0 | Windows | `run`: runs `params.script` (PowerShell) and returns output, errors and duration. Capability `adhoc_script` |
| `firmware` 1.3.0 | Windows | `scan`: the versions installed now (`components`: BIOS from `Win32_BIOS`, device firmware of class Firmware, non-Microsoft drivers of the main device classes from `Win32_PnPSignedDriver`; shown in the agent's Firmware tab) and BIOS, firmware and driver updates (with the installed version when known: the BIOS, HP `TargetVersion`) from Dell Command Update (`dcu-cli`, report and log in a fresh `ProgramData\Dell\open-rmm\<id>` folder, since DCU 5.x refuses other paths with exit code 107), Lenovo System Update (`tvsu`) or HP Image Assistant (business models); `install-tool`: installs the vendor tool with winget when missing (`Dell.CommandUpdate`, `Lenovo.SystemUpdate`, `HP.ImageAssistant` into `Program Files\HP\HPIA`), workstations only, then scans; `install`: `{"types":["firmware","driver"],"include_bios":false,"severity":"all"}`, never reboots (records the reboot for `reboot`), suspends BitLocker for one reboot before a BIOS update. `scan` never installs the tool: the agent page has an *Install* button, and a policy rule `firmware/install-tool` every 24 hours on clients installs it everywhere (without winget, distribute it from the Software page); other vendors are reported as not supported. Tool paths overridable (`dcu_path`, `tvsu_path`, `lenovo_wmi_class`, `hpia_path`) |
| `shell` 1.1.0 | Windows, Linux | `open` (`{"minutes":30}`, at most 60): interactive shell session (capability `interactive_shell`): the agent itself runs Windows PowerShell or bash on a pseudo-terminal, with the module's `Shell.ps1` / `shell.sh` as startup script. Refused unless the local policy `AllowInteractiveShell` is enabled; never in policies; opened from the agent page |
| `files` 1.0.0 | Windows, Linux | `open` (`{"minutes":60,"max_bytes":…}`, at most 240 minutes): interactive file session (capability `file_session`, served by the agent itself, 1.1.0 or later): browse, download, upload, new folder; the agent's own folders are refused. Opened from the agent page or for several agents from the bulk page; never in policies |
| `message` 1.0.0 | Windows | `send` (`title`, `text` up to 1000 characters, `icon` info/warning/error, `timeout_seconds`, `wait`): a message box in every active user session (WTSSendMessage, the agent runs as SYSTEM); the result says per session whether it was shown, confirmed or timed out. In the agent context menu |
| `adinventory` 1.1.0 | Windows | `collect`: computer objects of the endpoint's domain (name, OU, operating system, enabled, last domain logon) read with the computer account, at most 10,000; and the enabled user accounts with a name (account, UPN, given name, surname, display name), at most 20,000 and as many as fit in the result. Run it on the domain controllers or one member server. Results feed the *Active Directory* page, the OU tree and the search of computers by the name of their user |
| `workflow` 1.0.0 | Windows | `run`: a software distribution workflow of the console (see below), with the library packages it uses. Capability `adhoc_script`: approved with MFA, never in a policy, refused where `AllowAdHocScripts` is 0 |

## Distribution workflows

*Software → Workflow* holds workflows built in the console, each saved as a new, immutable revision with its author and comment. A revision (`internal/workflow`) has:

- **Detection rules**, joined by AND or OR: when they hold the computer is compliant and no step runs; after the steps they must hold, or the run fails (unless an installer asked for a reboot).
- **Steps**, run in order as SYSTEM: PowerShell script, command, download (a library package, or any URL with an optional SHA-256), HTTP `GET`/`POST` (headers and body), installation (MSI, Inno, NSIS, burn, exe with silent arguments; Authenticode checked unless allowed unsigned). A failed step stops the workflow unless it is marked to continue.
- **Conditions** on each step, joined by AND or OR, the same kinds as the detection rules: installed application (name with `*`, minimum version), registry key or value, file or folder (minimum file version), PowerShell script returning `$true`, **user in an AD group** (the logged-on user, or the last one) and **computer in an AD group**, nested groups included, read with the computer account. Any rule can be negated.

`%VARIABLE%` is expanded in paths, arguments, URLs, headers and bodies; `%RMM_WORK%` is the job's work folder, where downloads go. A workflow runs from *Actions on selected* (computers or a group) with one MFA approval: the console signs the latest revision as the job's parameters, with the library packages it uses (at most 5). The workflow page and the catalog show the latest run on each computer: installed, already compliant, running or failed.

## Automatic collection

Nothing has to be configured for data to arrive: the console keeps in every tenant an **automatic collection** policy that runs, on every approved agent, the newest published version of:

| Module · action | Every | Where |
|---|---|---|
| `inventory` · `collect` | 24 h | all |
| `winupdate` · `scan` | 24 h | all |
| `osupdate` · `scan` | 24 h | all (Linux; agents of other platforms skip it) |
| `winget` · `scan` | 24 h | all |
| `firmware` · `scan` | 24 h | all |
| `protection-status` · `status` | 1 h | all |
| `accesslog` · `collect` | 5 min | all |
| `trendmicro` · `status` | 15 min | where a Trend Micro agent service exists |
| `adinventory` · `collect` | 24 h | domain controllers (`NTDS` service) |

Collections whose module is not published are left out; the policy is updated when modules are published, at startup and every hour. The first run on a new agent comes within two minutes. It is signed by the signer **without an operator's approval** because the signer accepts only this exact list (`policy.CheckBaseline`): fixed modules, actions and intervals, no parameters, no windows. What runs is still the module version pinned by hash and signed with the module release key. Operators cannot edit or delete it.

## Scheduled rules (advanced)

To run other module actions periodically, or only on endpoints where a condition holds (for instance a reboot in a maintenance window), create a **policy** (*Settings → Scheduled rules*, Admin role). Each rule names a module version, an action, parameters, an interval and an optional condition. Saving asks for a new MFA sign-in; the signer signs that exact version and the agents receive it at once. Results of the latest run of each rule appear on the agent page. Modules with the `adhoc_script` capability cannot be used in policies.

For example, a policy with one rule `{"id": "inventory", "module": "inventory", "version": "1.0.0", "action": "collect", "every": "24h"}` keeps every endpoint's inventory up to date; new endpoints send it within a couple of minutes of receiving the policy.

Planned plugins and how they are activated automatically by policies: [ARCHITECTURE.md](ARCHITECTURE.md) §3.7 and §8.
