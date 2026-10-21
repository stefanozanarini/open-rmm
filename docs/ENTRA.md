# Microsoft Entra ID setup

Operators sign in to the console with Entra ID (Microsoft 365), and every command needs a fresh Microsoft sign-in with MFA. Setting it up takes about 10 minutes in the [Entra admin center](https://entra.microsoft.com) (or the Azure portal), with an Application Administrator account or higher.

You need: the console address (`OPENRMM_PUBLIC_URL`, e.g. `https://rmm.example.com`).
You get: two IDs for `.env` and a client secret file for `setup-secrets.sh`.

> **Two pages, one application.** Entra shows the application in two places, with different menus:
> - **App registrations** (*Registrazioni app*): redirect URI, secret, roles. Steps 1–4.
> - **Enterprise applications** (*Applicazioni aziendali*): who may sign in. Step 5.
>
> If you created the app from *Enterprise applications → New application*, its App registration exists too: search **App registrations** in the top bar → tab **All applications** → your app.

## 1. Register the application

**App registrations → New registration**

- Name: `open-rmm console`
- Supported account types: **this organizational directory only**
- Redirect URI: platform **Web**, `https://<console address>/auth/callback`

From the **Overview** page copy the **Application (client) ID** and the **Directory (tenant) ID**.

If the app already exists, add the redirect URI under **Manage → Authentication** (shown as *Authentication (Preview)* in newer portals): **Add a platform / Add redirect URI → Web**. Leave implicit grant (access tokens, ID tokens) **off**.

**Optional claims** (skip with `OPENRMM_MFA_CLAIM=none`, step 6). Entra leaves the MFA claims out of v2.0 ID tokens unless they are requested; without them every sign-in is refused with *multi-factor authentication is required*.

- `acrs:c1`: **Manage → Token configuration → Add optional claim** → token type **ID** → tick **acrs** → **Add**.
- `amr`: it is not in that list. **Manage → Manifest**, add to `optionalClaims.idToken` `{ "name": "amr", "source": null, "essential": false, "additionalProperties": [] }`, **Save**.

## 2. Client secret

**Manage → Certificates & secrets → Client secrets → New client secret**, expiry 12 months.

Copy the **Value** column with its copy icon (about 40 characters, often with a `~`), **not** the *Secret ID* (a GUID). It is shown only once. Do not screenshot it or paste it in chats or tickets. Write it straight to a file on the console host, one line, nothing else:

```bash
umask 077; cat > ~/client-secret.txt    # paste, Enter, Ctrl-D
```

Then `deploy/setup-secrets.sh ~/client-secret.txt` and delete the file. Set a reminder: before it expires, create a new secret and repeat.

## 3. App roles

**Manage → App roles → Create app role**, three times, allowed member types **Users/Groups**:

| Display name | Value | Allows |
|---|---|---|
| open-rmm Administrator | `OpenRMM.Admin` | Everything: revoke agents, tokens, settings, publishing, commands |
| open-rmm Operator | `OpenRMM.Operator` | View everything, approve new agents and run commands |
| open-rmm Reader | `OpenRMM.Reader` | Read only |

The **Value** must be exactly as above. An app created from *Enterprise applications* may also list `User` and `msiam_access`: leave them, but never assign them (they give no access to the console).

## 4. Values for .env

```bash
OPENRMM_OIDC_ISSUER=https://login.microsoftonline.com/<Directory ID>/v2.0
OPENRMM_OIDC_CLIENT_ID=<Application ID>
OPENRMM_MFA_CLAIM=amr              # none, amr or acrs:c1: see step 6
OPENRMM_TENANT_MAP=<Directory ID>=<open-rmm tenant ID>
```

The open-rmm tenant ID is printed by `openrmm-admin tenant create` ([INSTALL.md](INSTALL.md) §4). Several open-rmm tenants for the same operators: `<Directory ID>=<tenant1>|<tenant2>`.

## 5. Who can sign in

**Admin consent** (once, for all users). Most tenants do not let users consent to apps, and the first sign-in stops on *Approval required*. **App registrations → open-rmm console → Manage → API permissions → Grant admin consent for <organization>**, as Global Administrator or Privileged Role Administrator. The app asks only for `openid`, `profile` and `email` (shown as *User.Read*, *View users' basic profile*, *Maintain access*).

**Enterprise applications → open-rmm console**:

- **Properties → Assignment required: Yes**, so only assigned users can even try.
- **Users and groups → Add user/group**: pick a user or (better) a group such as `open-rmm-admin`, and the role **open-rmm Administrator** (or Operator / Reader). If the roles do not show up yet, wait a minute and reload.

## 6. MFA

The console accepts a sign-in or a command only when the token proves MFA.

**Left to Entra** (`OPENRMM_MFA_CLAIM=none`): the console does not check MFA in the token and relies on the directory requiring it (security defaults or per-user MFA for every operator). Simplest setup, no optional claims needed; make sure no operator can sign in with a password alone. Every command still needs a new sign-in (`prompt=login`).

**Checked by the console, without Entra ID P1** (`OPENRMM_MFA_CLAIM=amr`): MFA must be on for the operators (security defaults, or per-user MFA). The console checks that the token's `amr` claim contains `mfa`, and still asks for a new sign-in (`prompt=login`) at every command, but Entra may reuse a recent MFA.

**With Entra ID P1** (included in Microsoft 365 Business Premium, E3, E5; recommended): MFA is required again at **every** command.

1. **Protection → Conditional Access → Authentication contexts → New**: name `open-rmm command`, ID `c1`, publish to apps.
2. **New policy** "open-rmm: MFA for commands": users = the operators; target resources = **Authentication context `c1`**; grant = **Require authentication strength** (*Phishing-resistant MFA*, or at least *Multifactor authentication*); session = **Sign-in frequency: Every time**.
3. **New policy** "open-rmm: console access": target = the *open-rmm console* app; grant = *Require multifactor authentication*.
4. In `.env`: `OPENRMM_MFA_CLAIM=acrs:c1`.

## First sign-in

Open the console address and sign in. If access is refused, `docker compose logs server` says why. For MFA it shows the `amr` and `acrs` values received. Common causes:

| Symptom | Cause |
|---|---|
| Entra error *AADSTS50011* (redirect URI mismatch) | The redirect URI in step 1 differs from `OPENRMM_PUBLIC_URL` + `/auth/callback` |
| Entra error *AADSTS7000215* (invalid client secret) | The *Secret ID* was copied instead of the *Value*, or the secret expired |
| Entra page *Approval required* / *Need admin approval* | Admin consent of step 5 not granted yet |
| Entra error *AADSTS50105* (not assigned) | User not assigned in step 5 |
| Console: no role | Assigned with `User`/`msiam_access` instead of an open-rmm role |
| Console: MFA required, log `amr=[]` | Optional claim `amr` missing (step 1, *Token configuration*) |
| Console: MFA required, `amr` without `mfa` | The user signed in without MFA (enable MFA for that user), or `acrs:c1` without the policy of step 6 or the `acrs` optional claim |

## What the signing service checks

For every command, `openrmm-signer` checks on its own, without trusting the console:

- the token signature, with the public keys downloaded from Microsoft;
- issuer, audience (the application ID) and expiry;
- MFA, according to `OPENRMM_MFA_CLAIM`;
- that the authentication is at most 10 minutes old;
- the `OpenRMM.Operator` or `OpenRMM.Admin` role;
- that the operator's directory may manage that tenant;
- that the token `nonce` is the exact fingerprint of the command: agent, module, version, action, parameters, validity;
- that the token has not been used before.

Every signed command is also recorded in the signer's own log, independent from the console's.
