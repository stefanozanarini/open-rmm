# Agent updates

The agent updates itself, version by version and ring by ring, with automatic rollback when a new version does not work.

## How it works

1. On the offline machine a **release** is signed: agent and watchdog for one platform, described by a manifest signed with the **agent release key** (separate from the module and job keys).
2. The release is published on the console, which verifies the signature before accepting it.
3. A **target version** is set for a ring (`pilot` or `broad`) and a platform.
4. The gateway offers the release to the agents of that ring running an older version. The agent:
   - verifies the signature with the keys configured on the endpoint (`ReleaseSigningKeys`);
   - **refuses any version not newer than its own**;
   - downloads the executables, checks their hashes and installs them in `versions/<version>/`, next to the current version;
   - leaves the activation to the watchdog.
5. The **watchdog** checks the hash again, stops the agent, points the service to the new version and restarts it (`ImagePath` of the service on Windows, a systemd drop-in on Linux).
   - If the new version **does not reconnect to the console** within 10 minutes, it switches back to the previous one.
   - A rolled-back version is never offered again: a newer version is needed.
6. The new agent then updates the watchdog, with the same mechanism and rollback. The two never switch at the same time, so one is always there to repair the other.

Outcomes (downloading, staged, installed, rejected, rolled back) appear in the console, on the agent page and under **Aggiornamenti**, and in the audit log.

## Agent release key

Generate it on the offline machine, like the module key:

```bash
openrmm-admin signing keygen -out agent-release.key
```

Configure the public key on the agents as `ReleaseSigningKeys` (REG_MULTI_SZ, or `release_signing_keys` in the configuration file) and on the console in `OPENRMM_RELEASE_KEYS`, used to verify releases at publication.

## Publishing a version

The version must be the one built into the executables (`make build-windows VERSION=1.2.0`): the watchdog considers the update successful only when the agent reports exactly that version.

```bash
# offline machine
openrmm-admin release sign -version 1.2.0 -platform windows/amd64 \
  -agent bin/openrmm-agent.exe -watchdog bin/openrmm-watchdog.exe -key agent-release.key

# console
docker compose run --rm --user "$(id -u):$(id -g)" -v "$PWD:/in:ro" -e OPENRMM_RELEASE_KEYS admin \
  release publish -file /in/openrmm-1.2.0-windows-amd64.orel
```

## Rollout

```bash
# a few PCs in the pilot ring (the others stay in broad)
docker compose run --rm admin agents ring -tenant <TENANT> -agent <AGENT> -ring pilot

# pilot first...
docker compose run --rm admin release target -tenant <TENANT> -ring pilot -platform windows/amd64 -version 1.2.0
# ...then, after a few days without problems, everyone
docker compose run --rm admin release target -tenant <TENANT> -ring broad -platform windows/amd64 -version 1.2.0

docker compose run --rm admin release list -tenant <TENANT>
```

Connected agents receive the offer as soon as the target is set; switched-off ones at their next connection.

## Automatic restart

| Level | Windows | Linux |
|---|---|---|
| 1 | Service recovery actions: restart after 5 s, 30 s, then every 2 minutes | `Restart=always` |
| 2 | Watchdog: restarts the agent when stopped, or when its health file has not been refreshed for 5 minutes (at most 6 times an hour) | same |
| 3 | Scheduled task every 15 minutes: `sc.exe start` on watchdog and agent | systemd timer `openrmm-healthcheck` |

The third level uses only system programs with fixed paths, so it keeps working whatever version is installed.

## Current limits

- The mechanism is covered by automated tests: switch, rollback, tampered files, paths outside the versions directory, restart budget, offers signed with untrusted keys, altered files, rings, downgrades. **It has not been tried on real Windows nor with real systemd yet.**
- The initial installation (services, folders, scheduled task) is done by the MSI ([AGENT-INSTALL.md](AGENT-INSTALL.md)). For development there are `openrmm-agent install` and `openrmm-watchdog install`.
