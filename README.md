> **Installation transition:** Read [PUBLICATION_TRANSITION.md](PUBLICATION_TRANSITION.md) before using these rebuilt releases. Android requires a fresh installation and enrollment; all endpoints need the matching discovery namespace.

> **Audited fork:** download the reviewed container image from [GitHub Releases](RELEASES.md). Deployment files contain generic examples; supply private site configuration separately.

# STUNMESH — local OpenDHT/WireGuard fork

This home-use fork discovers endpoints behind NAT. **WireGuard authenticates peers and encrypts VPN traffic.** STUN and OpenDHT provide bounded, unauthenticated address hints; they cannot enroll a peer or change keys, PSKs or AllowedIPs. Public services can observe discovery metadata, poison hints or deny service. They do not relay established VPN traffic. Direct connectivity is still NAT-dependent; there is no relay fallback.

The Android companion is [stunmesh-android](https://github.com/snf/stunmesh-android), application ID `dev.stunmesh.local`. Both fork endpoints must use the new `stunmesh-hints-v2` namespace and version-2 public records. Upstream encrypted records are intentionally incompatible; there is no legacy fallback.

## What remains

- Container daemon for an existing kernel WireGuard interface, using the shared UDP proxy. No raw/pcap STUN, executable/shell/Cloudflare plugins or hosted release workflows.
- Android core using official `wireguard-go` and the same UDP socket for STUN and WireGuard. Discovery never receives a private key or PSK. In-process WireGuard key use is required and accepted.
- One-shot provisioning tool; the phone generates its own private key. A separate offline container generates enrollment files and confidential PSK-bearing QR codes on the administrator's machine or NAS.

The daemon's namespace `NET_ADMIN` authority can control its WG interface. This is a code-level separation of discovery from keys, not a sandbox around a compromised daemon. Pinning and isolation reduce supply-chain risk; they do not prove that upstream software or this fork has no vulnerabilities.

## Build and run

Follow [LOCAL_BUILD.md](LOCAL_BUILD.md) for pinned tools, isolated/offline tests, local AAR, image and separate APK signing. The `Dockerfile` is a **Podman** recipe. The minimal image contains the daemon, official `wg`, BusyBox/musl for interface setup, and a small reviewed entrypoint. It has no compiler, package manager, curl, QR library, source checkout or configuration.

[deploy/README.md](deploy/README.md) documents the rootless trial arrangement and configuration conversion. Do not deploy the old upstream image and the new Android app together. The current trial preserves the NAS encrypted-mount startup, service user/maps, Samba and NFS; Restic remains disabled. NFS retirement belongs to the subsequent preparation plan below. No firewall change is part of this implementation.

[Rootless container client](deploy/client/README.md) and [direct host client](deploy/client-host/README.md) are included in the current [release](RELEASES.md). The direct host client requires separate privileged setup; it does not change the NAS's rootless model. Deployment helpers use a pinned, rebuilt image. Real profiles, credentials and service-user ownership belong in private site configuration.

[OPERATIONS.md](OPERATIONS.md) describes service boundaries and remaining acceptance gates. Historical live-test results do not validate the newly named application, signer or discovery namespace. The current publication changes no running service. Previously reported credential rotation remains outstanding; see [SECRET_REVIEW.md](SECRET_REVIEW.md).

## Enroll and check a phone

Use the [server enrollment command](deploy/enrollment/README.md), then follow the
[phone connection checklist](deploy/enrollment/TESTING.md). Importing a QR creates
the phone identity; it does **not** authorize that identity on the server.
Both endpoints also need matching discovery versions before an external-network
test is meaningful. A VPN icon alone does not prove a WireGuard handshake.

The service and enrollment worker run in containers. The current administration
scripts still require **host Python 3 and Git**, and some service operations use
host `podman-compose`; Podman itself runs on the host. These are on-demand tools,
not new persistent services. This is not a fully containerized management layer.
No management-container migration or exemption from a site's dependency policy
is implied by this documentation. See the enrollment guide for the exact boundary.

[Syncthing setup](deploy/syncthing/README.md) uses the VPN only, with no direct
LAN/public sync port, and an extensible device/folder inventory. The guide records
the volume prerequisite and the remaining Android VPN-loss enforcement check.

## Security record

- [IMPLEMENTATION_PROGRESS.md](IMPLEMENTATION_PROGRESS.md): progress, commits and validation evidence.
- [SECURITY_REMEDIATION_PLAN.md](SECURITY_REMEDIATION_PLAN.md): agreed decisions and finding mapping.
- [SECURITY_AUDIT.md](SECURITY_AUDIT.md): original baseline audit, retained with its evidence. Findings describe the audited revision, not a claim that every old path remains in this fork.

Destination split routing is mandatory in the Android app: server /32 or /128 routes are preferred; bounded small service ranges are accepted. Ordinary phone internet and DNS use the underlay. Do not enable Android's “Block connections without VPN.” Routes select destinations, not individual ports/apps.

[VALIDATION.md](VALIDATION.md) records local acceptance results and residual risks. [ARTIFACT_MANIFEST.json](ARTIFACT_MANIFEST.json) identifies the signed APK, image and exact inputs.
