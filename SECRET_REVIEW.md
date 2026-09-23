# Credential review before the release commit — 2026-09-22

**2026-09-23 update:** the new Linux/services source and image publication review
is recorded at the end of this file. The NAS Samba tool-output incident is
separate; those credentials remain compromised and were re-exposed by a masking
error in the latest session. The older result below applies to the source/APK
material it lists, not to NAS credentials.

**Result: no real credential detected in either repository, its available local Git history, or the signed release APK. No compromised credential was identified for rotation.** Synthetic test keys are intentionally public and must never be used for real peers. This is a bounded review, not proof that arbitrary encoded or unknown secrets cannot exist.

## Reviewed material

| Repository snapshot before packaging | Commits | Blobs | Trees | Tags | Current files |
| --- | ---: | ---: | ---: | ---: | ---: |
| `snf/stunmesh-go` at `89d55b1f919c42bed3861ab0946c7d4d1d7943ed` | 628 | 2,065 | 1,872 | 14 | 369 |
| `snf/stunmesh-android` at `79c51ba0e834d418c82c804a9d6c5b589cab238e` | 148 | 479 | 742 | 7 | 184 |

- Read every available local Git object using `git cat-file --batch-all-objects` and `--batch`, including objects outside current branches, commit/tag messages and historical deleted files. Mapped paths through all refs/reflogs and inspected tracked/nonignored current files. These counts describe the baseline, before this documentation/artifact commit; the final staged changes were checked separately.
- Inspected the APK container and **all 139 decompressed entries**, including DEX, resources and both native libraries: 36,825,882 archive bytes / 36,854,304 decompressed bytes. Also inspected the historical Gradle wrapper JAR's entries. Historical image paths contain launcher icons, with no enrollment QR artifact found.
- Compared the actual local enrollment PSK, signing password, encrypted signing container and serialized signing private key against the reviewed bytes, with common encodings where applicable. **Zero matches.** Comparisons stayed in memory; values were not emitted, sent to a credential-validation service or included in this report. No phone private key or NAS private key was extracted for comparison.
- Applied private-key header, cloud/source-hosting/API token, credential URL/assignment, WireGuard hex/base64 and sensitive-filename checks; reviewed matches rather than excluding entire test directories. ASCII and UTF-16 representations were checked. No private signing/access/configuration file was found in the tracked or mapped historical paths.

## Candidate disposition

| Match class | Disposition |
| --- | --- |
| 29 credential-pattern groups | All reviewed: README placeholders, synthetic URL/redaction/parser canaries, generated-value concatenation, and signing-property variable references. No real token, password or private-key block found. |
| 2,745 distinct 32-byte base64 groups | Go dependency hashes, with their `go.sum` row syntax checked. Nine also appear in the APK's native Go build metadata. These are integrity metadata. |
| Eight other 32-byte base64 groups | Synthetic fixtures: five repeated-byte values, one single-nonzero-byte value and two ascending-byte sequences. Includes the public test PSK shared by Go and Android provisioning tests; it differs from the actual enrollment PSK. |
| Five other 32-byte base64 groups | Two documented owner **public** peer keys and three test **public** keys. They do not authorize a peer without its private key. |
| APK contents | No credential-pattern or known-credential matches. Its nine canonical 32-byte base64 groups are the dependency hashes above. The signing certificate/public key is expected public information. |

Public IP addresses, peer public keys, proposal identifiers, certificate fingerprints and artifact hashes in test reports are metadata, not credentials. Existing private signing files and confidential enrollment JSON/QR remain outside both repositories; their legitimate presence in the private workspace is not evidence of a leak into Git or the APK.

## Release and commit checks

- Versioned only the owner-signed `snf/stunmesh-android/releases/stunmesh-0.3.0-local.4.apk`, its checksum and provenance. SHA-256: `8bed3a5ec0196e6aa28ff4a7de1118e073a8e80f2399d0a58f8f8860f51e409e`.
- Android `apksigner` verifies its v3 signature with certificate SHA-256 `1e7a77c5f73ccb78259d60677e37147d7e50c5a50644e2ecb57cc6b58b1cef82`. Copied bytes match the artifact tested on the phone; no rebuild or source change.
- Added and checked ignore rules for local signing keys/passwords, ADB credentials, environment files and confidential enrollment files. Android permits only the named release APK; synthetic public fixtures remain trackable. Ignore rules reduce accidental additions and do not replace review.
- Explicitly staged reviewed paths; checked the staged content for credential matches, APK checksum/signature identity and `git diff --cached --check`. No history rewrite, push or GitHub release publication.

The review covers the local objects available at the listed snapshots and these packaging changes. It does not examine inaccessible remote history, prove absence of steganographic/obfuscated secrets, or replace the separate source/dependency audit. Any future real credential discovered in a commit must be treated as compromised and rotated; deleting the current file alone is insufficient.

## Linux client publication review — 2026-09-22

The owner requested publication under `operator` after confirming the laptop's rootless VPN connection. The outgoing Go branch and `linux-client-v0.1.0` image were rechecked before publication:

- At parent `6532959`, scanned all 630 commits, 2,082 blobs, 1,878 trees and 14 tag objects locally available, plus 381 current tracked/nonignored files including the new service and release documentation. New final documentation/index content receives a separate staging check.
- Verified the OCI archive SHA-256 and every OCI blob digest. Inspected metadata and every entry in its sole layer, including all five files: BusyBox, musl loader, `wg`, `stunmesh-go`, and entrypoint. The image has no mounted configuration, keys, compiler or source checkout. The release uploads only that unchanged OCI archive and its checksum file.
- Added the fresh laptop's actual private key and PSK to the existing in-memory known-credential/encoding comparisons. **Zero known-credential matches, zero new unreviewed credential-pattern or 32-byte-base64 candidates, and no sensitive current/historical filenames.** The 19 pattern groups and 2,756 base64 groups also occur at previously reviewed immutable history locations; dispositions above remain applicable. No matched secret value is emitted or published.
- Added ignore guards for real `wg*.conf`, `stunmesh.yml` and a client `config/` directory; placeholder `*.example` files remain tracked. The actual laptop config, enrollment material, ADB credentials, APK signing material and NAS private repository are not included in the GitHub upload. Android is unchanged by this publication.

This finding is limited to the source/image publication. The separate NAS inventory incident in `CLIENT_PROGRESS.md` exposed Samba credentials in tool output; those still require rotation. No additional real credential leak was found in this publication review. Pattern matching and known-value comparisons cannot prove that an unknown or deliberately obfuscated secret is absent.

## Direct client/services publication review — 2026-09-23

- Scanned every locally available Go Git object/ref/reflog and current
  tracked/nonignored files. The full scan at `2c10ce4` covered 643 commits,
  2,176 blobs, 1,925 trees and 15 pre-existing tag objects, plus 416 current files.
  Staged documentation was checked before publication; the new annotated tag
  and release body contain only reviewed public metadata.
- Verified the new OCI archive and every blob, then scanned metadata and all
  five runtime files. Image ID
  `sha256:7203a28d29c83d4d64561c049bba967d9b96d2e3c7c1709c4626ff3cd0e764eb`;
  archive SHA-256
  `afa228bc05e26577aa81c193ccba5dd66273d207c6fb0d9182a473bfcbddc2d4`.
- In-memory exact/encoding checks additionally included NAS WG configuration
  keys/PSKs, the new NAS-issued laptop profile, previous rootless laptop,
  retired external-test identity and active Samba passwords, including their
  short literal forms. Existing enrollment/signing comparisons also ran.
  **Zero known-secret matches.** No phone private key was extracted.
- All 2,756 base64 candidate groups match the previously reviewed set of
  dependency hashes/public values/synthetic fixtures. No new image base64
  candidate is absent from the previously reviewed image. The 23 credential
  pattern groups include the prior placeholders/canaries plus four new source
  expressions: official `wg` command names and test-key concatenation.
  None contains a real issued profile or credential; no sensitive public path
  was found. No credential-validation request was sent to an external service.
- Android source and its existing signed APK are unchanged. NAS `/srv` retains
  intended canonical secrets in its local-only Git repository, as authorized;
  that repository, real profiles and temporary test credentials are excluded
  from public commits and release assets.

Two incidents were disclosed and documented in `EXECUTION_PROGRESS.md`: the
Samba masking failure re-exposed passwords in tool output, and the initial
provisioner put the NAS WG private key, configured peer PSKs and unused laptop
private key into local journald logs. Capturing Podman stdout did not prevent
log retention. These are real exposures despite the clean public source/image
scan. Existing client private keys were not in those provisioning results.

The new image writes confidential outputs only to exclusive 0600 files; helper
containers also disable logging. The duplicate stdout Linux provisioner was
deleted and regression tests added. Existing server/peer/Samba rotation remains
deferred; the unused laptop identity was revoked/replaced after the owner
raised the NAS keyring quota. Recovery checked 194 new journal entries with
zero matches for the relevant old/new credentials. Journal evidence/private
Git history were not erased. The v0.2.0 prerelease contains only reviewed
code/image assets; the subsequent recovery clears its initial installation hold.
These checks cannot prove absence of unknown/obfuscated secrets.

The published v0.2.0 OCI archive and SHA256SUMS were downloaded again; both match the recorded expected SHA-256. Publication does not resolve the documented journal/tool-output incidents. NAS deployment was separately recovered; older affected credentials still need rotation.

After laptop identity replacement, the scan included both the current and retired
laptop credentials plus the existing NAS/client/Samba secret set. At parent
`ec6b0af`, 644 commits, 2179 blobs, 417 working files and the five-file OCI image
yielded zero known-secret matches; the 23 pattern and 2756 key-candidate groups
were unchanged from the reviewed set. The recovery documentation and evidence
were included as working files.

The startup-helper continuation at `e9b19bc` was scanned across 647 commits,
2195 blobs, 417 working files and the unchanged OCI image: zero known-secret
matches, with the same 23 pattern and 2756 key-candidate groups. During the
actual NAS startup check, 36 new journal entries also had zero matches for the
checked current VPN/Samba credentials. These checks do not rotate previously
exposed credentials. Subsequent evidence contains only counts, public container
names and commit identifiers.
