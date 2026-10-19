# Microsoft Entra ID setup

The console uses Entra ID (Microsoft 365) for operator sign-in and to approve every single command. Everything is configured in the customer's [Entra admin center](https://entra.microsoft.com), with an Application Administrator account or higher.

> **To verify on the real tenant.** The flow has been tested with a test OIDC provider, and discovery against Microsoft's servers works, but a real sign-in on an Entra tenant has not been tried yet. At the first sign-in check the server logs (`docker compose logs server`): if access is refused for MFA, the message shows the `amr` and `acrs` values received.

## 1. App registration

**Identity → Applications → App registrations → New registration**

| Field | Value |
|---|---|
| Name | `open-rmm console` |
| Supported account types | Accounts in this organizational directory only |
| Redirect URI | **Web** platform: `https://console.example.com/auth/callback` (same host as `OPENRMM_PUBLIC_URL`) |

Note the **Application (client) ID** and **Directory (tenant) ID** from the Overview page.

## 2. Client secret

**Certificates & secrets → New client secret**, 12-month expiry. Copy the **value** into a file at once and use it with `setup-secrets.sh`, which installs it for the container. Before it expires, create a new secret and repeat.

## 3. App roles

**App roles → Create app role**, three times (allowed member types: *Users/Groups*):

| Display name | Value | Allows |
|---|---|---|
| open-rmm Administrator | `OpenRMM.Admin` | Everything: approve and revoke agents, create tokens, run commands |
| open-rmm Operator | `OpenRMM.Operator` | View everything and run commands |
| open-rmm Reader | `OpenRMM.Reader` | Read only |

## 4. Who can sign in

**Enterprise applications → open-rmm console**:

- **Properties → Assignment required: Yes.** Otherwise any user of the directory could attempt to sign in (the console would still refuse users without a role).
- **Users and groups → Add assignment**: assign the roles, preferably to dedicated groups (e.g. `open-rmm-admin`).

## 5. MFA

The console accepts sign-ins and commands only when the token proves MFA. Two ways:

### With Entra ID P1 (recommended)

Entra ID P1 is included in Microsoft 365 Business Premium, E3 and E5. With P1, MFA is required **at every command**:

1. **Protection → Conditional Access → Authentication context → New**: name `open-rmm command`, ID `c1`, published to apps.
2. **New policy** "open-rmm: MFA for commands":
   - Users: the operators (or everyone).
   - Target resources: **Authentication context → `c1`**.
   - Grant: **Require authentication strength** → *Phishing-resistant MFA* (FIDO2, Windows Hello for Business, passkeys), or at least *Multifactor authentication*.
   - Session: **Sign-in frequency → Every time**.
3. **New policy** "open-rmm: console access": resource the *open-rmm console* app, grant *Require multifactor authentication*.
4. In `.env`: `OPENRMM_MFA_CLAIM=acrs:c1`.

The console requests context `c1` both at sign-in and for every command, and Entra puts it in the `acrs` claim of the token only when the policy has been satisfied.

### Without P1

With Entra *security defaults* MFA is mandatory, but it cannot be forced again at every command: Entra may consider a recent MFA still valid. The console still requires a new sign-in (`prompt=login`) for every command.

In `.env`: `OPENRMM_MFA_CLAIM=amr`. The console checks that the `amr` claim contains `mfa`. Verify this mode at the first sign-in: if Entra does not include `amr` in the token, sign-in is refused and the log says so.

## 6. Values for .env

```bash
OPENRMM_OIDC_ISSUER=https://login.microsoftonline.com/<Directory ID>/v2.0
OPENRMM_OIDC_CLIENT_ID=<Application ID>
OPENRMM_MFA_CLAIM=acrs:c1          # or amr
OPENRMM_TENANT_MAP=<Directory ID>=<open-rmm tenant ID>
```

The open-rmm tenant ID is the one returned by `openrmm-admin tenant create`. With several open-rmm tenants managed by the same operators: `<Directory ID>=<tenant1>|<tenant2>`.

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
