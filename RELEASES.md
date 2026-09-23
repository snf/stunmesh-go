# Go/container releases

Download [STUNMESH 0.3.0](https://github.com/snf/stunmesh-go/releases/tag/v0.3.0). Assets: `stunmesh-linux-amd64.oci.tar`, `SHA256SUMS`, `PROVENANCE.json`. Binaries and runtime credentials are not ordinary committed files.

**Coordinated migration required:** both endpoints must use `stunmesh-hints-v2`. Provisioning schemas and deployment names also changed; read [PUBLICATION_TRANSITION.md](PUBLICATION_TRANSITION.md). This release was rebuilt from the cleaned source, not renamed from the retired image. No running host/service was changed.

| Property | Value |
| --- | --- |
| OCI archive SHA-256 | `315bcc64b85294c329d0caa25a9b139879e6a7087557ca484d8ee9ae92eea1e8` |
| Image configuration ID | `sha256:2570f2efddc079baa05449d2e4be854ab472f816b752fdbd7873b14893fa041d` |
| Platform | Linux/amd64 |
| Contents | Daemon, official `wg`, BusyBox, musl loader and entrypoint; no configuration or credentials |

Download the archive and checksum asset into one directory, run `sha256sum -c SHA256SUMS`, then `podman load -i stunmesh-linux-amd64.oci.tar`. Verify the loaded image ID. Rootless NAS operation and the optional privileged direct-host client have different authority requirements; review [operations](OPERATIONS.md), [rootless client](deploy/client/README.md) and [host client](deploy/client-host/README.md).

Public templates contain generic example addresses, service users and directories. Adapt them to private site configuration and review existing interfaces/containers before deployment. Preserve UID/GID mappings and ownership. No firewall, NFS or active file-sharing change is implied.

Go race tests/vet, helper checks and the rebuilt image's isolated kernel-WireGuard authentication tests passed. The companion [Android 0.3.1 release](https://github.com/snf/stunmesh-android/releases/tag/v0.3.1) requires a fresh install/enrollment. New end-to-end NAS/phone acceptance remains pending; public STUN/OpenDHT has no guaranteed relay fallback for every NAT.

Prior provisioning-log credential exposure still requires coordinated rotation. Clean publication does not undo that exposure. See [security review](SECRET_REVIEW.md), [artifact provenance](ARTIFACT_MANIFEST.json) and [build instructions](LOCAL_BUILD.md).
