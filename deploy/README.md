# Rootless Podman trial handoff

No NAS changes are made by the local build. The previously inspected arrangement was `/srv/containers/wireguard-trial`, rootless Podman called as `operator`; container UID 0 mapped to host `operator`. Recheck the current service/process UID/GID maps before deployment. Never use `sudo podman`, blanket chown/relabel, host networking, a runtime socket mount or `--privileged`. Preserve Samba/NFS, the encrypted-mount startup script and the disabled Restic configuration.

The template uses the existing trial addresses: NAS `10.77.0.1/32`, phone `.2/32`, temporary VPS `.254/32`. The entrypoint permits only these explicit addresses plus the prior `.253/32` trial peer; change that public allowlist deliberately in Git if needed. The phone's destinations must match the selected server services.

**Two different UDP ports are required:** kernel WG listens on `51822` inside the container; the shared proxy listens on `51820`. Publish only proxy port `51820/udp`. Using the same wildcard port for both cannot work. No `NET_RAW` is needed with this proxy implementation. Kernel WG creation requires `NET_ADMIN` in the owned network namespace; it does not grant host `NET_ADMIN` under rootless Podman.

Use the final image digest in `compose.example.yml`, not an upstream tag. Mount only a private configuration directory, read-only. No NAS data/share directory is required by discovery. Files remain owned by the existing service user; keep directory mode 0700 and key-bearing config 0600. Keep complete server configuration changes in the existing local private Git repository as requested; do not erase history. Never put a phone-generated private key in that repository.

`wg0.conf` is a **wg setconf** file (not wg-quick), containing the server's existing private key, `ListenPort = 51822`, and each authorized phone public key with its exact tunnel address and optional separately provisioned PSK. `PersistentKeepalive = 25` enables hole punching while idle. It must not contain Address/DNS/PostUp/PostDown hooks. Startup adds the reviewed address/routes inside the container only; no host firewall/sysctl is changed.

Example **public discovery overlay**, replacing the placeholder phone public key with the reviewed public reply and supplying the chosen real HTTPS proxy/STUN origins:

```yaml
refresh_interval: 180s
interfaces:
  wg0:
    protocol: ipv4
    proxy: {listen: 51820}
    peers:
      phone:
        public_key: REPLACE_WITH_PHONE_PUBLIC_KEY
        plugin: dht
        protocol: ipv4
plugins:
  dht:
    type: builtin
    name: opendht
    endpoints: [https://REPLACE_WITH_REVIEWED_PROXY]
    timeout: 10s
stun:
  addresses: [REPLACE_WITH_STUN_HOST:3478]
log: {level: info, format: json}
```

Plugin fields are flat in server YAML. Android JSON uses its own typed `config` object; do not copy that nesting here. Quote strings normally; numeric ports and boolean settings must retain their actual YAML types. Unknown fields, nulls, aliases and implicit scalar coercions are rejected. Raw mode (`proxy.enabled: false`) is unsupported.

A WG tunnel into this container does **not yet expose Samba/Syncthing in other container namespaces**. Before production use, inspect their current bindings and choose the smallest explicit service integration. Do not add general forwarding, NAT, a host route, shared namespaces or firewall rules speculatively. Any required change must state its exact scope and preserve LAN administration. This is a deployment input for the later server-access session, not a claim that the isolated trial provides NAS service access already.

Suggested later sequence: save current public runtime/mapping evidence; prepare the new config/image in an isolated trial directory; review `podman-compose --in-pod=false ... config`; start only this trial; run DEVICE_TESTS.md; commit approved config changes; keep the prior image/config for rollback. Stop/remove only the named trial container to roll back. Do not enable boot startup until routing, recovery and battery checks pass.
