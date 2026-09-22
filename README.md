# STUNMESH — local OpenDHT/WireGuard fork

This home-use fork discovers endpoints behind NAT. **WireGuard authenticates peers and encrypts VPN traffic.** STUN and OpenDHT provide bounded, unauthenticated address hints; they cannot enroll a peer or change keys, PSKs or AllowedIPs. Public services can observe discovery metadata, poison hints or deny service. They do not relay established VPN traffic. Direct connectivity is still NAT-dependent; there is no relay fallback.

The Android companion is `snf/stunmesh-android`, application ID `dev.stunmesh.local`. Both fork endpoints must use the new `stunmesh-hints-v2` namespace and version-2 public records. Upstream encrypted records are intentionally incompatible; there is no legacy fallback.

## What remains

- Container daemon for an existing kernel WireGuard interface, using the shared UDP proxy. No raw/pcap STUN, executable/shell/Cloudflare plugins or hosted release workflows.
- Android core using official `wireguard-go` and the same UDP socket for STUN and WireGuard. Discovery never receives a private key or PSK. In-process WireGuard key use is required and accepted.
- One-shot public provisioning tool; the phone generates its own private key. QR generation stays on the workstation.

The daemon's namespace `NET_ADMIN` authority can control its WG interface. This is a code-level separation of discovery from keys, not a sandbox around a compromised daemon. Pinning and isolation reduce supply-chain risk; they do not prove that upstream software or this fork has no vulnerabilities.

## Build and run

Follow [LOCAL_BUILD.md](LOCAL_BUILD.md) for pinned tools, isolated/offline tests, local AAR, image and separate APK signing. The `Dockerfile` is a **Podman** recipe. The minimal image contains the daemon, official `wg`, BusyBox/musl for interface setup, and a small reviewed entrypoint. It has no compiler, package manager, curl, QR library, source checkout or configuration.

[deploy/README.md](deploy/README.md) documents the rootless trial arrangement and configuration conversion. Do not deploy the old upstream image and the new Android app together. Preserve the existing NAS encrypted-mount startup, service user/maps, Samba and NFS; Restic remains disabled. No firewall change is part of this implementation.

[PROVISIONING.md](PROVISIONING.md) covers public-only enrollment, optional PSK handling and recovery. [DEVICE_TESTS.md](DEVICE_TESTS.md) is the later NAS/GrapheneOS gate, including actual routing, backup, handover and battery tests. Building the APK is not evidence that these hardware checks passed.

## Security record

- [IMPLEMENTATION_PROGRESS.md](IMPLEMENTATION_PROGRESS.md): progress, commits and validation evidence.
- [SECURITY_REMEDIATION_PLAN.md](SECURITY_REMEDIATION_PLAN.md): agreed decisions and finding mapping.
- [SECURITY_AUDIT.md](SECURITY_AUDIT.md): original baseline audit, retained with its evidence. Findings describe the audited revision, not a claim that every old path remains in this fork.

Destination split routing is mandatory in the Android app: server /32 or /128 routes are preferred; bounded small service ranges are accepted. Ordinary phone internet and DNS use the underlay. Do not enable Android's “Block connections without VPN.” Routes select destinations, not individual ports/apps.
