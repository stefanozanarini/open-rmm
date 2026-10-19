# Agent installation on Windows

The agent is installed with an MSI package, suitable for Group Policy (GPO) deployment. The package installs the agent and the watchdog as system services; the configuration comes from Group Policy (recommended) or from MSI properties.

## What you need

| Value | Where it comes from |
|---|---|
| Console address | `agent.example.com:443` (the agents endpoint) |
| Root certificate | `openrmm-admin pki root-b64 -in pki/ca/root-ca.crt` (one base64 line) |
| Enrollment token | web console → **Token**, or `openrmm-admin token create` |
| Command key | printed by `setup-secrets.sh` (`ed25519:…`) |
| Module key | public module release key (offline machine) |
| Release key | public agent release key (offline machine) |

## Building the package

```bash
make msi VERSION=1.0.0
# → dist/openrmm-agent-1.0.0-x64.msi
```

The package is built on Linux with msitools/wixl (in a container, or with `wixl` installed). CI builds it on every push and publishes it as an artifact.

> **Before production:** sign the executables and the MSI with Authenticode. Without a signature SmartScreen and some antivirus products may block them.

### Signing

Create the key and certificate on the build machine (options in [ARCHITECTURE.md](ARCHITECTURE.md) §12.1):

```bash
openrmm-admin codesign ca -dir codesign -org "Cliente Srl"       # dedicated CA
openrmm-admin codesign csr -dir codesign -org "Cliente Srl"      # or: request for AD CS / a public CA
```

```bash
openrmm-admin codesign check -cert codesign/codesign.crt -key codesign/codesign.key
```

```bash
make msi VERSION=1.0.0 SIGN_CERT=codesign/codesign.crt SIGN_KEY=codesign/codesign.key
```

Both executables are signed before they go into the MSI, then the MSI itself, with an RFC 3161 timestamp (`SIGN_TIMESTAMP` changes the server). Paste `codesign.crt` in the console (**Configurazione → Firma del codice**) to download the certificates for Group Policy and get a warning before expiry. With a dedicated CA, deploy `codesign-ca.cer` to *Trusted Root Certification Authorities* and `codesign.cer` to *Trusted Publishers*; with AD CS only `codesign.cer` is needed.

## Group Policy deployment (recommended)

1. **Administrative templates.** Copy to the domain *Central Store* (`\\domain\SYSVOL\domain\Policies\PolicyDefinitions`):
   - `packaging/admx/open-rmm.admx`
   - `packaging/admx/en-US/open-rmm.adml` into the `en-US` subfolder (and `it-IT` if needed).
2. **Configuration.** In the computers' Group Policy Object: **Computer Configuration → Policies → Administrative Templates → open-rmm**:
   - console address and enrollment token;
   - *Trust and keys*: root certificate and the three public keys;
   - *Local policies*: whether ad-hoc PowerShell scripts are allowed, concurrent commands.
3. **Installation.** Copy the MSI to a network share readable by the computers (e.g. `\\fileserver\deploy$\open-rmm\`), then **Computer Configuration → Policies → Software Settings → Software installation → New → Package → Assigned**.

At the next restart the PCs install the agent, which enrolls and appears in the console **pending approval**.

Group Policy values take precedence over those written by the MSI and stay under the domain's control. If the MSI is installed before the policies arrive, the services keep running and retry reading the configuration every minute.

**The token in Group Policy is readable by every user of the PC.** Therefore:

- use a token **without automatic approval** and with a number of uses close to the number of PCs;
- give it a short expiry and remove it from the GPO when the rollout is done;
- approve in the console only the PCs you recognize.

## Manual installation or other tools

```bat
msiexec /i openrmm-agent-1.0.0-x64.msi /qn ^
  SERVER=agent.example.com:443 ^
  ENROLLTOKEN=<token> ^
  ROOTCA=<base64 of the root CA> ^
  JOBSIGNINGKEYS=ed25519:... ^
  MODULESIGNINGKEYS=ed25519:... ^
  RELEASESIGNINGKEYS=ed25519:... ^
  ALLOWADHOCSCRIPTS=1
```

The values go to `HKLM\SOFTWARE\open-rmm`. At first start the agent:

- restricts that key's permissions to SYSTEM and Administrators;
- deletes the token once enrolled.

## What gets installed

| Item | Where |
|---|---|
| Agent and watchdog | `C:\Program Files\open-rmm\versions\<version>\` |
| Services | `openrmm-agent`, `openrmm-watchdog` (LocalSystem, delayed automatic start, automatic restart on failure) |
| Configuration and state | `C:\ProgramData\open-rmm\` (SYSTEM and Administrators only) |
| Periodic check | Scheduled task `\open-rmm\Controllo servizi`, every 15 minutes |

What the MSI cannot express is applied by the services themselves at every start:

- recovery actions and delayed start;
- scheduled task;
- registry and folder permissions.

## Updates and removal

- After installation the agent **updates itself from the console** ([UPDATES.md](UPDATES.md)), not through a new MSI. If you redeploy an MSI, use a version **not older** than the one the agents already run: the MSI points the service back to its own version.
- Removal (Programs and Features, `msiexec /x`, or removal from the GPO) deletes services, scheduled task, every installed version and the agent state, including its private key. Revoke the agent in the console afterwards.

## Tests done and limits

- The package tables are checked at every build: services, registry values, secure properties, action sequence.
- The package has been installed and removed with the msiexec of **Wine 10**:
  - installation with properties succeeded and both services started;
  - the agent enrolled on a real gateway and appeared pending approval;
  - the token was removed from the registry after enrollment;
  - removal deleted the data and the private key.
- **Not tried on real Windows yet:**
  - Group Policy deployment;
  - registry and folder permissions;
  - scheduled task;
  - restart after the service is stopped.
