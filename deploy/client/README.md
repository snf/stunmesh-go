# Headless Podman client

The existing reviewed image already implements both WireGuard peers. The client uses the same five-file image as the NAS, a different private identity, and a read-only configuration directory. There is no UI, new daemon, proxy protocol, dependency or authentication scheme. WireGuard authenticates the peer; SSH and Samba retain their normal service authentication.

For a new checkout, use the release tag rather than the fork's old upstream `main`:

```sh
git clone --branch linux-client-v0.1.0 https://github.com/snf/stunmesh-go.git
cd stunmesh-go
```

## Rootless first

This stage gives **the client container** a VPN route to `10.77.0.1/32`. Normal laptop traffic and the host's routes/DNS are unchanged. Host applications can use `podman exec` or the SSH configuration below; this stage does not make the laptop a transparent LAN VPN client.

Requirements: a Linux host with working rootless Podman, user/network namespaces, kernel WireGuard and a functioning `pasta` networking backend (including `/dev/net/tun`). Tested remotely with Podman 5.4.2. A restricted development container can prevent nested Podman operation even when `unshare --user --net` works; run these commands on the laptop host.

The exact locally built image is published as a Linux/amd64 OCI archive in [linux-client-v0.1.0](https://github.com/snf/stunmesh-go/releases/tag/linux-client-v0.1.0). It is also in `stunmesh-build/artifacts/handover/stunmesh-linux-amd64.oci.tar` next to the original checkout. Its SHA-256 is `8020acf13bae04463a09289615e7591653b84da3e84e04ca5c9e11878af11380`; see [build provenance](../../ARTIFACT_MANIFEST.json). On another machine, download the versioned asset into the same external layout (skip this when the verified local archive already exists):

```sh
gh release download linux-client-v0.1.0 --repo snf/stunmesh-go \
  --pattern stunmesh-linux-amd64.oci.tar --pattern SHA256SUMS \
  --dir ../stunmesh-build/artifacts/handover
```

Run from the Go repository root. Verify against the checksum committed in this checkout before loading:

```sh
(cd ../stunmesh-build/artifacts/handover && sha256sum -c -) < releases/SHA256SUMS
podman load -i ../stunmesh-build/artifacts/handover/stunmesh-linux-amd64.oci.tar
export STUNMESH_IMAGE=sha256:470285618081f8b2ecb049f0b8280a815b9a7d88bbed2c6933ad1e7a34d7d8e8
export STUNMESH_CONFIG=/absolute/path/to/private/client-config
podman run -d --name stunmesh-client --pull=never \
  --network=pasta:--ipv4-only -p 51830:51830/udp \
  --user 0:0 --cap-drop=all --cap-add=NET_ADMIN \
  --security-opt=no-new-privileges --read-only --pids-limit=128 \
  --restart=no --stop-timeout=15 \
  -e TUNNEL_ADDRESS=10.77.0.254/32 -e TUNNEL_ROUTES=10.77.0.1/32 \
  -v "$STUNMESH_CONFIG:/config:ro" \
  --tmpfs /run:rw,nosuid,nodev,noexec,size=4m,mode=755 \
  "$STUNMESH_IMAGE"
```

Run from the Go repository root. The external directory must already contain `wg0.conf` and `stunmesh.yml`; examples in this directory contain placeholders and deliberately cannot connect. Use directory mode 0700 and file mode 0600, owned by the rootless Podman user. Keep real keys outside this source repository and out of shell arguments/logs. Do not mount a home directory, SSH agent, runtime socket or NAS data into the client.

Use official `wg genkey`, `wg pubkey` and `wg genpsk` to provision a separate client identity and per-client PSK. The `wg` executable is already inside the image. The NAS must authorize the corresponding public key/PSK for **only `10.77.0.254/32`**, add that return route, and include the public key in its STUNMESH discovery configuration. Do not run multiple clients with this identity/address simultaneously, or copy Android's identity. An identity used on a temporary test VPS must be revoked before enrolling a fresh laptop-only identity.

The kernel WG socket uses 51828; discovery uses the separate shared UDP socket 51830, published with the same port number. No TCP port is published by this client. The optional `192.168.0.10:51824` endpoint is the explicit home-LAN bootstrap; outside home, STUN/OpenDHT supplies a public endpoint. No relay fallback is provided. The 180-second refresh and 25-second WG keepalive reuse the existing bounded recovery behavior.

Check only public status fields; `wg showconf` and `wg show ... dump` can expose credentials:

```sh
podman exec stunmesh-client wg show wg0 latest-handshakes
podman exec stunmesh-client wg show wg0 transfer
podman exec stunmesh-client /bin/busybox ip route get 10.77.0.1
podman exec stunmesh-client /bin/busybox ip route get 1.1.1.1
```

The first route must use `wg0`; the second must use the normal container uplink. A running container or published discovery hint is not evidence of an authenticated tunnel; verify a fresh WG handshake and real service traffic. Rootless services normally need a logged-in user session or deliberately configured user lingering to survive logout; do not silently enable lingering during a trial.

Stop with `podman stop stunmesh-client`; restart with `podman start stunmesh-client`. To remove only this client after stopping it, use `podman rm stunmesh-client`. Host routes stay unchanged and the private mounted configuration is retained. If you prefer Compose, the equivalent definition is `compose.yml` in this directory; use `podman-compose --in-pod=false -f deploy/client/compose.yml up -d` instead of the `podman run` command, with the same two exported variables.

## Rootless systemd service

The [Quadlet definition](stunmesh-client.container) runs the same image and networking configuration as the plain Podman command. Use Podman 5.4 or later with systemd and cgroup v2. Quadlet generates the service; there is no wrapper daemon, scheduled health check, image auto-update or background build. Process failures receive at most three startup attempts per five minutes, with ten seconds between attempts. Network recovery remains the existing daemon's responsibility. A running service is not proof of a WG handshake.

Install it from the Go repository root as the same ordinary user that loaded the image. Set `STUNMESH_CONFIG` to the already-provisioned private directory; the original laptop uses `../stunmesh-laptop/config`. These commands copy the private files to a stable user configuration location outside Git. Do not use another device's identity or substitute the placeholder examples.

```sh
export STUNMESH_CONFIG="$(realpath ../stunmesh-laptop/config)"
install -d -m 0700 "$HOME/.config/stunmesh" "$HOME/.config/stunmesh/client"
install -m 0600 "$STUNMESH_CONFIG/wg0.conf" "$HOME/.config/stunmesh/client/wg0.conf"
install -m 0600 "$STUNMESH_CONFIG/stunmesh.yml" "$HOME/.config/stunmesh/client/stunmesh.yml"
install -d -m 0700 "$HOME/.config/containers/systemd"
install -m 0644 deploy/client/stunmesh-client.container "$HOME/.config/containers/systemd/"
```

When replacing the existing manual trial, stop and remove **only its container** before starting the service. This briefly interrupts the VPN and retains the external private configuration:

```sh
podman stop stunmesh-client
podman rm stunmesh-client
systemctl --user daemon-reload
systemctl --user start stunmesh-client.service
systemctl --user status stunmesh-client.service
podman exec stunmesh-client wg show wg0 latest-handshakes
```

For a fresh installation there is no old container to stop/remove. Thereafter manage it with `systemctl --user start|stop|restart stunmesh-client.service`; do not run the Compose/manual client at the same time. Existing `podman exec` SSH commands still work while the service runs. Quadlet removes its disposable container on stop; keys remain in the mounted directory. Failed config checks or repeated failures can be retried after correcting the cause with `systemctl --user reset-failed stunmesh-client.service` followed by `start`.

The service is **on-demand by default**. To start it with the user session, deliberately add a drop-in; generated Quadlet services cannot be enabled using ordinary `systemctl enable`:

```sh
install -d -m 0700 "$HOME/.config/containers/systemd/stunmesh-client.container.d"
cat > "$HOME/.config/containers/systemd/stunmesh-client.container.d/autostart.conf" <<'EOF'
[Install]
WantedBy=default.target
EOF
systemctl --user daemon-reload
```

This does not enable user lingering; without an active user manager the rootless service does not run. To undo automatic startup, remove only that `autostart.conf` drop-in and reload the user manager. The Quadlet passes the Podman 5.4.2 generator and systemd unit validation; its first real laptop-managed start/stop/reboot is a separate check from the completed manual-container test. See the [official Quadlet documentation](https://docs.podman.io/en/v5.4.1/markdown/podman-systemd.unit.5.html).

## SSH from the laptop and onward to home machines

The NAS SSH forwarder listens at `10.77.0.1:22`. Add a host-specific entry to your SSH configuration, using an already verified NAS host key and the appropriate existing identity:

```sshconfig
Host nas-vpn
    HostName 10.77.0.1
    HostKeyAlias nas
    User operator
    ProxyCommand podman exec -i stunmesh-client /bin/busybox nc %h %p
    StrictHostKeyChecking yes
    ForwardAgent no
```

Then `ssh nas-vpn` reaches the NAS through WireGuard. `ssh -J nas-vpn user@192.168.0.X` reaches another home machine through the NAS SSH jump host. SSH keys remain on the laptop; they are not copied or agent-forwarded into the VPN container or NAS. Ordinary SSH authorization and forwarding policy still apply. For a selected web service, an SSH local forward through this alias is also available while the rootless trial is in use; do not bind that local forward to all interfaces.

## NAS services

The optional [service overlay](../services.compose.yml) adds two small forwarders using the **same existing image**. They share only the VPN network namespace, have no configuration/key/data mounts, and bind only `10.77.0.1:22` and `10.77.0.1:445`. `169.254.1.2` is Podman's `pasta` host-access address, verified on this NAS. Each forwarder gets only namespace `NET_BIND_SERVICE`, a read-only rootfs, no-new-privileges, and bounded process/memory limits. No host forwarding, NAT or firewall rule is added.

Restart/recreate **the whole VPN Compose group**, including forwarders, when recreating the VPN network namespace. Restarting only the VPN container can leave sidecars attached to its former namespace. NFS, the existing Samba container and LAN listeners remain unchanged. Samba users still need their own credentials; the passwords exposed during inventory need rotation separately.

Syncthing is not running on the inspected NAS. Its existing GUI binds to `127.0.0.1:8384` **inside its own container**, and the saved GUI has no authentication. Before starting it, review folder mounts/UIDs, configure the GUI appropriately, publish it only to host loopback, and add VPN-bound TCP forwards for GUI 8384 and sync 22000. Preserve disabled global discovery/relays/NAT traversal and use explicit `tcp://10.77.0.1:22000` device addresses. No UDP discovery/QUIC forward is required for this TCP-only design. Do not claim Syncthing access until its service is started and tested.

## Later privileged host-routing stage

The owner approved a rootless test first, followed by a container with the permissions needed for direct host access. That later stage must use a dedicated host WG interface name, preserve other VPN interfaces, add only selected service routes (initially `10.77.0.1/32`), and remove only its own interface/routes on shutdown. Keep the normal default route and DNS. **Do not switch this rootless Compose file to host networking unchanged:** its current entrypoint creates `wg0` inside a disposable namespace and has no host cleanup contract.

Direct host routing would allow ordinary applications to use `10.77.0.1` without per-application proxies. Routing an entire home LAN is a separate decision: it also needs a return path/gateway policy on the NAS and conflict handling when a hotel uses the same subnet. The current first-stage SSH jump host covers access to other machines without adding that routing complexity or changing the NAS firewall.

Reference: [Podman 5.4 networking and rootless options](https://docs.podman.io/en/v5.4.1/markdown/podman-run.1.html#network-mode-net). Test evidence and remaining work are tracked in [CLIENT_PROGRESS.md](../../CLIENT_PROGRESS.md).
