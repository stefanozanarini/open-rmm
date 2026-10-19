# Federation: a central console for several customer consoles

A managed-service provider runs one **central console**; each customer runs its own **customer console** with its agents, database and signer. A link lets the provider's operators do, from the central console, everything they could do on the customer console — while the customer console keeps its data, its signing key, its audit log and the power to cut the link.

Both are the same open-rmm software; federation is a link, not a different product. Two levels at most: a central console is not itself linked to another one.

## How it works

```
operators' browsers ──HTTPS──► central console ◄──link (TLS 1.3, pinned, outbound from the customer)── customer console ── agents
                                     │                                                                     │
                            Entra ID of the provider                                    signer (trusts the provider's directory
                                                                                         for commands, if configured)
```

- **The customer console opens the link**, outbound, to the central console's link listener. No inbound port at the customer. Both sides are authenticated by pinned certificates: the customer's is registered by a one-time token, the central's is in the token.
- **Every page is served by the customer console.** When a central operator opens a customer, the central console forwards each request over the link with the operator's identity; the customer console renders the page with its own data and checks (roles, CSRF, validation) and records every action in **its** audit log, marked "via central console". Nothing is copied to the central console except a periodic summary for the dashboard (agents, online, pending, open and critical alerts, missing security updates, pending reboots).
- **Commands are still signed by the customer's signer.** Approving a command or a policy from the central console means signing in again with MFA to the provider's Entra ID; the resulting id_token, bound to the exact request, goes to the customer console, which verifies it and passes it to its signer. The signer accepts it only if the customer configured it to trust the provider's directory. The central console never holds a customer's signing key and cannot create commands by itself.
- **The customer stays in control:** it chooses the highest role central operators get (Admin, Operator or Reader), can suspend the link at any time (tunnels close within seconds) or remove it. The link settings are never reachable from the central console.

Trust, in short: a central console that is compromised could read the customer's data and do what its role allows in the console (e.g. approve an agent, create a token); it could not run a command or change a policy without a provider operator's fresh MFA approval of that exact request.

## Central console

1. In `deploy/.env`:

   ```
   OPENRMM_FEDERATION_LISTEN=:8445
   OPENRMM_FEDERATION_BIND=0.0.0.0:8445
   OPENRMM_FEDERATION_PUBLIC_ADDR=central.msp.it:8445
   ```

   Publish port 8445 to the internet (or to the networks the customer consoles come from). The web console itself stays on the provider's LAN or VPN.
2. **Linked consoles (Console collegate) → New link**: give the customer's name. The page shows a **link token** once (valid 24 hours, single use). Send it to the customer's administrator over a channel you trust.

## Customer console

1. The provider gives its Entra directory id (tenant id) and the central console's application (client) id. In `deploy/.env` of the customer:

   ```
   OPENRMM_FEDERATION_ISSUER=https://login.microsoftonline.com/<provider tenant id>/v2.0
   OPENRMM_FEDERATION_CLIENT_ID=<central console application id>
   OPENRMM_FEDERATION_TENANT_MAP=<provider tenant id>=<open-rmm tenant id of this console>
   OPENRMM_FEDERATION_MAX_ROLE=OpenRMM.Admin
   ```

   These settings go to both the web console and the signer (`docker compose up -d`). They are deliberately in the deployment configuration, not in the web console: a web console administrator alone cannot let another directory approve commands.
2. **Linked consoles → Link to a central console** (Admin): paste the link token. The customer console creates its link key, connects and registers. From then on it keeps the link open.
3. **Suspend** closes the link at once; **Resume** reopens it; **Remove** deletes the link key (the provider must create a new link to reconnect).

## Entra ID of the provider

The central console's application registration needs, besides its own redirect URI, nothing more: step-up sign-ins for customer commands happen on the central console (`/auth/callback`) with the same application. The app roles assigned to provider operators (OpenRMM.Admin, Operator, Reader) apply to customer consoles too, capped by each customer's maximum role.
