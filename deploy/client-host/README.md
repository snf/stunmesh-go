# Direct laptop access

Linux/amd64, Podman 5.4+, systemd/Quadlet, Python 3.9+, iproute2 and OpenSSH.
NAS provisioning also uses its existing `podman-compose` and coreutils `timeout`.
NAS stays rootless. This laptop service needs host root and NET_ADMIN to install
normal host routes; it has no UI, default VPN route, extra daemon or firewall rule.
Use the [operations guide](../../OPERATIONS.md) for NAS, sync and backup status.

**Hold installation:** the NAS keyring quota currently blocks VPN restart and
replacement of the journal-exposed unused laptop identity. The prerelease
commands below are the handoff procedure after recovery. Do not download the
existing private profile until replacement is
confirmed in the operations guide.

## Retrieve the one device-specific file and verified image

The NAS reserves a separate laptop identity at `10.77.0.253/32`.
Its confidential canonical profile stays in private `/srv` Git. The previous
rootless `.254` identity is retained for rollback. Do not copy either identity
onto a second machine or commit the profile to this public repository.
The first unused identity needs replacement after a provisioning journal
exposure. See the unresolved NAS/older-client
[credential rotation](../../OPERATIONS.md#coordinated-rotation-not-yet-applied).

```sh
git clone --branch linux-client-v0.2.0 https://github.com/snf/stunmesh-go.git
cd stunmesh-go
install -d -m 0700 "$HOME/.config/stunmesh"
(umask 077; scp operator@192.168.0.10:/srv/containers/stunmesh-audit-trial/issued/laptop.json \
  "$HOME/.config/stunmesh/laptop.json")

curl -fL https://github.com/snf/stunmesh-go/releases/download/linux-client-v0.2.0/stunmesh-linux-client-v0.2.0.oci.tar \
  -o /tmp/stunmesh-linux-client-v0.2.0.oci.tar
printf '%s\n' 'afa228bc05e26577aa81c193ccba5dd66273d207c6fb0d9182a473bfcbddc2d4  /tmp/stunmesh-linux-client-v0.2.0.oci.tar' | sha256sum -c -
podman load -i /tmp/stunmesh-linux-client-v0.2.0.oci.tar
sudo podman load -i /tmp/stunmesh-linux-client-v0.2.0.oci.tar
./scripts/vpn-client check --config "$HOME/.config/stunmesh/laptop.json"
```

Pinned image ID: `sha256:7203a28d29c83d4d64561c049bba967d9b96d2e3c7c1709c4626ff3cd0e764eb`.
Rootless and rootful Podman have separate stores, hence the two explicit loads.
The archive contains five runtime files, no device profiles or source checkout.

`check` validates the profile through the pinned binary, displays only public
fields and the exact `/etc/hosts` diff, rejects route/address/alias collisions,
custom policy routing, mount dependencies and SSH configuration overrides.
Review any NFS/automount use of `nas` before replacing that name. Existing
aliases beyond `nas`, `home21`, `home23` require explicit profile changes.
Only the listed initial ports have forwards; the entire LAN is a separate stage.

## Install only after those checks

Keep a working LAN SSH session. Stop the old rootless client before starting the
new one (if a user Quadlet manages it, stop that service first):

```sh
systemctl --user stop stunmesh-client.service  # only if installed
podman stop stunmesh-client                  # only if running
sudo ./scripts/vpn-client install --config "$HOME/.config/stunmesh/laptop.json" --apply-hosts
sudo /usr/local/libexec/stunmesh/vpn-client start
sudo /usr/local/libexec/stunmesh/vpn-client status
```

Installation copies helpers into a root-owned location, config into
`/etc/stunmesh/laptop.json` (0600), and installs the rootful Quadlet. It applies
the reviewed hosts block and exact unreachable guard routes. **It does not start
the VPN or enable automatic VPN startup.** Only the guard oneshot is enabled at
boot. There is no polling guard process. Its failure is a systemd failure that
must be investigated; do not assume manual routing changes preserve the guard.

| Destination | VPN route and initial service |
|---|---|
| `nas` | `10.77.0.1/32`: SSH 22, SMB 445; Syncthing TCP 22000 after enrollment |
| `home21` | `10.77.0.21/32`: SSH 22 to `192.168.0.11`; reserved while offline |
| `home23` | `10.77.0.23/32`: SSH 22 to `192.168.0.12` |
| `nas-lan`, `home21-lan`, `home23-lan` | Original LAN IPs, explicit recovery paths |

No `192.168.0.0/24` or default route is installed. The numeric LAN bootstrap
`192.168.0.10:51824` cannot recurse through the `nas` hosts mapping. The host
interface is `wg0`, WG port 51832, discovery proxy 51834. Guard metric 42777 is
overridden by active route metric 50. Both use protocol 186 (often displayed as
`bgp` by iproute2); no BGP daemon is involved. Install refuses existing overlaps.

## Verify and stop

```sh
getent ahostsv4 nas
ip route get 10.77.0.1
ip route get 10.77.0.23
ip route get 1.1.1.1
ssh -o StrictHostKeyChecking=yes operator@nas
sudo /usr/local/libexec/stunmesh/vpn-client stop
ip route get 10.77.0.1  # must report unreachable with the tunnel stopped
ssh operator@nas-lan    # LAN escape route, when at home
```

Preserve SSH host-key verification. `.23` must authenticate its own SSH server,
not NAS. A new name may need an explicitly verified `HostKeyAlias` for its
already-trusted identity; do not accept an unverified key merely to make a test
pass. A successful literal LAN-IP connection is not proof of VPN use.

Existing agent/workspace containers may retain their own old hosts file.
`check` prints `--add-host` launcher arguments; use them when recreating those
containers and check their own resolution/route. Do not grant host networking
or extra capabilities just for DNS. A bridge-based namespace needing forwarding
requires a separate review; no installer rule silently enables it.

Normal shutdown cleans the owned interface; a root-owned runtime receipt records
its kernel index and public key for crash cleanup. A failed preflight cannot
remove an existing interface merely because its key matches. A replacement
interface is also refused. A kill during the short interval before a receipt is
written deliberately requires manual inspection: startup refuses the stale
interface instead of guessing ownership. This is not a claim of completed
reboot/suspend testing on the actual laptop.

Uninstall uses the installed helper:

```sh
sudo /usr/local/libexec/stunmesh/vpn-client uninstall
```

It restores the saved hosts file only if the installed hosts snapshot still
matches, then removes only the managed routes/units/helper. If hosts changed,
review and merge the saved `/etc/stunmesh/hosts.before` rather than overwriting
other changes. Private config/snapshots remain in `/etc/stunmesh`; archive
that directory deliberately before a fresh installation.

## NAS issuance and revocation

The existing profile is ready; do **not** issue it again. To change an identity,
use `scripts/vpn-peer` as the rootless NAS user. `issue-linux` refuses an existing
file, generates keys with the official `wg` tool offline, checks server address
collisions and refuses output inside a Git repository with a remote.
`activate`/`revoke` validate candidate WG configuration in a disposable network
namespace before a locked file transaction. Without `--restart-group`, only
stored configuration changes; `--restart-group` recreates the reviewed NAS
VPN/forwarder group and briefly interrupts it. Commit the issued profile and
canonical server files **only in private `/srv` Git**. This is intentionally
different from Android enrollment, which never accepts a phone private key.
Confidential issuance/candidate results are written directly to private files;
helper containers also disable logging. Capturing `podman` stdout alone does
not prevent the container log driver from retaining that output.
Group recreation checks key-count/byte headroom before stopping anything and
has a bounded timeout. This catches the observed quota exhaustion, but is not a
general host-capacity or kernel-leak repair.
