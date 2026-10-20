# Modules

Every open-rmm feature is a module (plugin): the agent only downloads, verifies and runs them. A new feature is added by publishing a module, **without updating the agent**.

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

## Signing and publishing

**From the console** (recommended). Once, a console administrator creates the module and release keys on the **Installer** page (*Module and release keys*), with the passphrase of the code-signing key: installers include the public keys from then on. Then, to publish:

1. zip the module folder (the one with `manifest.json`; the SDK is added automatically);
2. **Moduli → Pubblica un modulo**: sign in again with MFA, upload the zip, enter the passphrase.

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
| `inventory` 1.0.0 | Windows, Linux | `collect`: hardware, OS, BitLocker, battery, network, installed software, Supremo/AnyDesk/TeamViewer ids. Results become the agent's inventory in the console |
| `accesslog` 1.0.0 | Windows | `collect`: new logon events since the previous run (local, RDP, failures, lockouts). The console stores them and raises alerts for unusual logons |
| `trendmicro` 1.0.0 | Windows | `status`: Trend Micro products installed, versions, services; one check per product. Parameters: `expect`, `products`, `definitions` (override service names) |
| `protection-status` 1.0.0 | Windows | `status`: antivirus in Windows Security Center, Defender, firewall; checks `antivirus`, `defender`, `firewall` |
| `winupdate` 1.0.0 | Windows | `scan`: missing updates, pending reboot, WSUS/Intune management; `install`: by classification or KB, never reboots, refuses on managed endpoints unless `allow_managed` |
| `winget` 1.0.0 | Windows | `scan`: applications with an available upgrade; `upgrade`: `{"ids":[…]}` or `{"all":true,"exclude":[…]}` |
| `reboot` 1.0.0 | Windows | `reboot`: only if pending, with notice to logged-on users, skipped on low battery; use it in a policy with a maintenance window |
| `software` 1.0.0 | Windows | `install`: the package of the job (MSI, Inno, NSIS, burn, exe with silent switches), Authenticode check; `uninstall`: `{"product_code":"{…}"}` or `{"name":"…","version":"…"}`, silent only. Used by the *Software* page and the uninstall buttons |
| `script` 1.0.0 | Windows | `run`: runs `params.script` (PowerShell) and returns output, errors and duration. Capability `adhoc_script` |
| `firmware` 1.1.0 | Windows | `scan`: BIOS, firmware and driver updates from Dell Command Update (`dcu-cli`), Lenovo System Update (`tvsu`) or HP Image Assistant (business models); `install`: `{"types":["firmware","driver"],"include_bios":false,"severity":"all"}`, never reboots (records the reboot for `reboot`), suspends BitLocker for one reboot before a BIOS update. The vendor tool must be installed (Software page: `Dell.CommandUpdate`, `Lenovo.SystemUpdate`, HP Image Assistant uploaded to the library); other vendors are reported as not supported. Tool paths overridable (`dcu_path`, `tvsu_path`, `lenovo_wmi_class`, `hpia_path`) |
| `shell` 1.0.0 | Windows, Linux | `open` (`{"minutes":30}`, at most 60): interactive shell session (capability `interactive_shell`): the agent itself runs Windows PowerShell or bash on a pseudo-terminal, with the module's `Shell.ps1` / `shell.sh` as startup script. Refused unless the local policy `AllowInteractiveShell` is enabled; never in policies; opened from the agent page |
| `adinventory` 1.0.0 | Windows | `collect`: computer objects of the endpoint's domain (name, OU, operating system, enabled, last domain logon) read with the computer account; at most 10,000. Run it on the domain controllers or one member server. Results feed the *Active Directory* page and the OU tree |

## Policies

To run a module action periodically, or only on endpoints where a condition holds, create a **policy** in the web console (**Policy**, Admin role). Each rule names a module version, an action, parameters, an interval and an optional condition. Saving asks for a new MFA sign-in; the signer signs that exact version and the agents receive it at once. Results of the latest run of each rule appear on the agent page. Modules with the `adhoc_script` capability cannot be used in policies.

For example, a policy with one rule `{"id": "inventory", "module": "inventory", "version": "1.0.0", "action": "collect", "every": "24h"}` keeps every endpoint's inventory up to date; new endpoints send it within a couple of minutes of receiving the policy.

Planned plugins and how they are activated automatically by policies: [ARCHITECTURE.md](ARCHITECTURE.md) §3.7 and §8.
