# Go/container releases

Download [Owner v0.2.1](https://github.com/snf/stunmesh-go/releases/tag/v0.2.1). Its assets are the Linux/amd64 OCI image `stunmesh-linux-amd64.oci.tar`, `SHA256SUMS` and provenance JSON. Binary artifacts and private runtime configuration are not committed files.

This is a publication/privacy update using the same tested image as the preceding Linux client prerelease. The image's runtime source and dependencies were not changed by history sanitization.

| Property | Value |
| --- | --- |
| OCI archive SHA-256 | `afa228bc05e26577aa81c193ccba5dd66273d207c6fb0d9182a473bfcbddc2d4` |
| Image configuration ID | `sha256:7203a28d29c83d4d64561c049bba967d9b96d2e3c7c1709c4626ff3cd0e764eb` |
| Platform | Linux/amd64 |
| Contents | Daemon, official `wg`, BusyBox, musl loader and entrypoint; no runtime credentials/configuration |

Download the image and checksum asset to one directory and run `sha256sum -c SHA256SUMS`, then `podman load -i stunmesh-linux-amd64.oci.tar`. Verify the loaded image ID above. The rootless NAS deployment and optional privileged direct-host Linux client have different authority requirements; review [deployment guidance](OPERATIONS.md) before starting either.

Public deployment files contain generic example addresses, aliases and directories. Adapt them to private site configuration; do not apply them to an existing installation unchanged. History rewriting did not modify any running service. Keep private configuration and enrollment outside this public repository.

Native WireGuard authentication, split routing, helper lifecycle and synthetic service/backup tests have passed. Actual OS recovery, extended reliability and battery measurements remain outside completed acceptance. Discovery still depends on public STUN/OpenDHT and has no guaranteed relay fallback for every NAT.

Older local deployments affected by provisioning output captured in logs must rotate affected credentials. This release's file-only provisioning and disabled helper logging prevent the identified retention path; publishing clean source does not repair prior exposure. See [credential/privacy review](SECRET_REVIEW.md).

The companion [Android release](https://github.com/snf/stunmesh-android/releases/tag/v0.3.0-local.4) retains its existing owner signing identity and supports Obtainium.
