# Syncthing through the VPN only

This supersedes the earlier LAN/loopback publication and fixed three-device
plan. Production remains disabled until native device identities, folder paths
and permissions are approved. Do not start the legacy Compose service.

## Transport policy

| Component | Required configuration |
| --- | --- |
| NAS | Join the existing rootless VPN container's network namespace; listen only on `tcp://10.77.0.1:22000`. No Podman port publication or TCP forwarder. |
| Laptop | Join its own rootless VPN client container's namespace; contact only `tcp://10.77.0.1:22000`. Incoming sync listeners are disabled. |
| Android | Configure the NAS peer with only `tcp://10.77.0.1:22000`; no LAN address or `dynamic` fallback. Clear **Sync Protocol Listen Addresses** (no incoming sync listener), keep the GUI on loopback, and do not configure direct laptop/phone peering. |
| All instances | Disable global/local discovery, relays, NAT traversal, usage/crash reporting and automatic core upgrades. Use explicit TCP listeners, not `default` (which includes QUIC/relays). No router forwarding or public GUI. |

The NAS is the sync hub. Only clients initiate connections; the established
native Syncthing TLS session carries changes in both directions. NAS peers retain
the native `dynamic` sentinel with **both discovery services disabled**: this
resolves to no discovered dial targets, not public discovery. Only explicitly
approved device IDs and folder memberships are accepted. `allowedNetwork` is
restricted to `10.77.0.0/24`; it is an address filter, not a firewall or proof of
the network interface used. Other phone/laptop traffic retains its ordinary
internet route. No host/router firewall change is part of this setup.

The laptop launcher verifies a native WG route to the NAS and installs a lower
priority `unreachable` route for that exact destination inside the **container
namespace**. It persists if the WG interface is removed, preventing fallback to
the namespace's underlying default route. No host route is changed. A rootful
host-network VPN needs its separately reviewed host-route guard; this rootless
launcher deliberately refuses that network mode.

**Android enforcement remains an acceptance gate.** A static VPN destination,
disabled incoming listeners and discovery remove configured alternate sync paths;
they do not create an OS per-app kill switch. With Android's global "Block
connections without VPN" disabled for destination split routing, connection
attempts may use the normal network after the VPN disappears. Do not claim zero
underlay packets without testing/enforcement. Syncthing-Fork's inspected run
conditions do not supply a VPN-required control. Keep phone sync stopped when the
VPN is off pending that decision/test; this is an interim operating rule, not
automatic enforcement. Do not silently enable global lockdown and break ordinary
phone internet. Sources: [native config](https://docs.syncthing.net/users/config.html),
[TCP dialer](https://github.com/syncthing/syncthing/blob/main/lib/connections/tcp_dial.go),
[Android run conditions](https://github.com/researchxxl/syncthing-android/blob/main/app/src/main/java/com/nutomic/syncthingandroid/service/RunConditionMonitor.java).

## Volume record and storage

`volume.json` describes the **unlocked filesystem**, not a device or peer. Record
its mountpoint, source, filesystem type and filesystem UUID once, using the
[example](volume.example.json) and a verified mount inventory. Verify it before
generation and every start; never overwrite it automatically when the filesystem
is absent or its UUID changes. Existing deployments may already have this file.

All NAS sync roots and the index database must resolve below this same mounted
large volume. Identity/configuration remain in the private configuration Git
repository. The guard rejects a missing/wrong filesystem, paths outside it, and
cross-filesystem nested mounts. Each enabled folder also needs an existing
`.stfolder` directory and access under the real rootless UID/GID mappings.
Do not create data directories on the small root filesystem when the volume is
locked, use `:U`, or recursively change data ownership.

Adding another device on that filesystem needs **no new volume record**. Add
only its approved directory, inventory membership and narrowly scoped bind mount.
A separate filesystem requires a separately reviewed volume record/workflow.

## Identities and an extensible inventory

Each device generates its own native identity; share only its public Device ID.
No identity is generated or replaced by editing an inventory. NAS/laptop identity
generation retains the existing `syncthing-admin generate` workflow; a fresh
generation refuses existing state. Android creates its identity in the app.

Use [nas.inventory.example.json](nas.inventory.example.json) and
[laptop.inventory.example.json](laptop.inventory.example.json). Replace every ID
placeholder; these are intentionally invalid until completed. `devices` maps
labels to public IDs. Each local folder declares its path, type and explicit
device membership. Client inventories contain only that client and the NAS;
the NAS inventory contains all approved clients. There is no three-device limit
and adding a device does not automatically share any folder with it.

Pair while Syncthing and its temporary GUI are stopped:

```sh
syncthing-admin pair --root /PRIVATE/CONFIG_ROOT \
  --state-dir /LARGE/VOLUME/STATE --volume-file /PRIVATE/volume.json \
  --role nas --inventory /PRIVATE/nas.inventory.json
```

The reviewed inventory is saved as `CONFIG_ROOT/inventory.json`. Pairing preserves
existing folder versioning, keeps identities unchanged and pauses every folder.
The old `--nas-id/--laptop-id/--android-id` interface is replaced by `--inventory`.
For a laptop use its own role label and inventory; omit `--volume-file` only when
the existing non-NAS workflow permits it. Private paths and IDs never belong in
this public repository.

The service manifest independently lists data mounts, enabled folder IDs and
the existing `vpn_container` name. Remove mounts for retired sources. Keep
`approved: false` and `enabled_folders: []` until reviewed. `syncthing-service
check --manifest ...` verifies the mounted filesystem, inventory, folder paths,
markers and access. Start only after checking the actual container UID/GID/ACL
view. The GUI stays disabled in production. Temporary administration publishes
only host loopback, mounts no sync data and is stopped after use.

**Lifecycle:** stop Syncthing before recreating its VPN container, then start
Syncthing against the new namespace. Do not leave it holding the old namespace.
Removing the old Syncthing TCP forwarder is necessary before direct NAS binding
to the same port. The existing manual encrypted-volume startup approach stays.

The wrappers still use the existing host Python/Git/Podman administration layer;
no new host dependency or persistent daemon is added. The Syncthing core,
identity generation, GUI and runtime execute in containers. Full containerization
of the management wrappers is a separate unresolved boundary.

## Adding a later phone

Enroll its compatible VPN client first, then obtain a fresh native Syncthing ID.
Add its ID and only the selected memberships to the NAS inventory. For separate
camera storage, add a separate folder ID/path and receive-only NAS folder; keep
the existing phone's ID/path unchanged. Add the corresponding data bind mount,
verify the existing volume record and permissions, re-pair, review, then activate
only that folder. Client availability and iOS background restrictions are a
separate future acceptance phase; no iPhone compatibility is asserted here.

## Acceptance before enabling real data

Require listener inspection (no wildcard/LAN host TCP 22000, UDP 22000/21027 or
GUI port), approved IDs, a disposable bidirectional file test, preserved host
ownership, and a failed new sync attempt with the VPN unavailable. Test Android
underlay behavior separately; a VPN icon or private destination is insufficient.
Then repeat over an external network once discovery versions agree. Keep the
native watcher and conservative full-rescan interval; no extra poller, watchdog
or battery exemption is introduced. Sync deletion semantics still require
versioning/backup; disabled Restic is not an active backup.
