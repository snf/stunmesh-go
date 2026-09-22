# Rootless Podman trial handoff

No NAS changes are made by the local build. The previously inspected arrangement was `/srv/containers/wireguard-trial`, rootless Podman called as `operator`; container UID 0 mapped to host `operator`. Recheck the current service/process UID/GID maps before deployment. Never use `sudo podman`, blanket chown/relabel, host networking, a runtime socket mount or `--privileged`. Preserve Samba/NFS, the encrypted-mount startup script and the disabled Restic configuration.

The template uses the existing trial addresses: NAS `10.77.0.1/32`, phone `.2/32`, laptop `.254/32`. The external client test used a temporary identity at `.254`, revoked before enrolling the laptop-only identity. The entrypoint permits only these explicit addresses plus the prior `.253/32` trial peer; change that public allowlist deliberately in Git if needed. Client destinations must match the selected server services.

**Two different UDP ports are required:** kernel WG listens on `51824`; the shared STUN/WG proxy listens on `51826`. Publish both only on the NAS LAN address, with identical container/host port numbers. The phone's explicit LAN bootstrap endpoint is `NAS_LAN_IP:51824`; public discovery advertises the proxy socket. Using the same wildcard port for both cannot work. No `NET_RAW` is needed. Kernel WG creation requires `NET_ADMIN` in the owned network namespace; it does not grant host `NET_ADMIN` under rootless Podman.

The real phone test found that sending LAN traffic to the proxy fails: its mapping contains the peer's STUN-discovered public endpoint, while LAN packets arrive from a private address. Direct kernel WG authenticates those packets and handles authenticated roaming; the discovery controllers preserve a healthy WG endpoint. This avoids adding LAN hint schemas or unauthenticated source-learning to the proxy. Keep this explicit LAN listener distinct from the external proxy path, which still requires carrier/NAT testing. Port translation also caused the first trial to advertise a different port from its LAN listener; preserve port numbers through Podman. No host firewall change is required for these LAN-bound mappings.

Use the final image digest in `compose.example.yml`, not an upstream tag. Mount only a private configuration directory, read-only. No NAS data/share directory is required by discovery. Files remain owned by the existing service user; keep directory mode 0700 and key-bearing config 0600. Keep complete server configuration changes in the existing local private Git repository as requested; do not erase history. Never put a phone-generated private key in that repository.

`wg0.conf` is a **wg setconf** file (not wg-quick), containing the server's existing private key, `ListenPort = 51824`, and each authorized phone public key with its exact tunnel address and optional PSK included in the confidential enrollment record. `PersistentKeepalive = 25` enables hole punching while idle. It must not contain Address/DNS/PostUp/PostDown hooks. Startup adds the reviewed address/routes inside the container only; no host firewall/sysctl is changed.

Example **public discovery overlay**, replacing the placeholder phone public key with the reviewed public reply and supplying the chosen real HTTPS proxy/STUN origins:

```yaml
refresh_interval: 180s
interfaces:
  wg0:
    protocol: ipv4
    proxy: {listen: 51826}
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

A WG tunnel alone does not expose services in other namespaces. The optional [service overlay](services.compose.yml) now provides VPN-bound SSH and SMB forwards through Podman's host-access address; both paths were tested from an external rootless client. These two limited forwarders share the VPN network namespace and have no key/data/configuration mounts. No host forwarding, NAT, route or firewall change is involved. Syncthing remains stopped pending its own configuration and ownership review. See the [headless client instructions](client/README.md) and [execution record](../CLIENT_PROGRESS.md). General LAN routing is a separate later decision.

Suggested later sequence: save current public runtime/mapping evidence; prepare the new config/image in an isolated trial directory; review `podman-compose --in-pod=false ... config`; start only this trial; run DEVICE_TESTS.md; commit approved config changes; keep the prior image/config for rollback. Stop/remove only the named trial container to roll back. Do not enable boot startup until routing, recovery and battery checks pass.
