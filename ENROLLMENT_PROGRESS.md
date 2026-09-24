# Server-side Android enrollment helper

- [x] Read-only server configuration import; native WireGuard PSK generation.
- [x] Private JSON and SVG output, no private phone key handling.
- [x] Reserve live/pending phone addresses; reopen existing enrollment safely.
- [x] Offline rootless helper container; no live peer authorization or restarts.
- [x] Build and pin the three-executable provisioning image.
- [x] Test real container issuance, QR decoding, errors, permissions and logging.
- [x] Install private site settings/helper; verify without issuing a real phone identity.
- [x] Commit code, documentation and private installation; provide the one command.

The existing runtime namespace differs from the new Android release. Generating
an enrollment does not complete the separate coordinated discovery migration.
Public files contain generic examples only; site settings and credentials stay
in the existing local-only NAS configuration repository.

Validation completed with disposable identities: live/pending/service-address
exclusions, idempotent re-open, private Git commits, owner-only permissions,
remote-repository refusal, non-TTY refusal, and actual interactive QR rendering.
Independent ZXing 3.5.3 decoding matched the SVG's exact enrollment JSON. The
final image's issuance test found zero credential matches in 18 new journal
entries. All 20 Python helper tests and the focused Go race tests passed.

Installed helper/settings without issuing a production-phone enrollment; the
real server configuration parsed successfully in an offline preflight stopped
before key generation. Existing container IDs and VPN configuration stayed
unchanged. No phone software, firewall or live peer changed.

Known-secret scanning passed for public source/history and all three enrollment
executables. The live VPN image and Android APK were not rebuilt or changed.

Documentation follow-up: added a release-phone checklist covering explicit
server authorization, matching discovery versions, real-service traffic,
VPN-off control, mobile/hotspot and return-home checks. Clarified that current
administration scripts use host Python/Git (and some use podman-compose);
containerizing those scripts remains unresolved. No runtime or dependency
change was made as part of this documentation update. Site observations belong
only in the private deployment repository.

Startup follow-up: the old container entrypoint accepted only the original
trial peer addresses, so newly allocated phones could not receive a persistent
return route. The guard now accepts explicitly selected canonical host `/32`s
in the existing trial subnet; it adds no default/subnet route or peer authority.
Three regression tests cover all 254 permitted host addresses, invalid/broad/
outside routes, shell syntax and interface-address restrictions. The candidate
also passed an offline rootless kernel WireGuard/startup test with existing
peers and a newly enrolled phone, using the deployed daemon version. A read-only
startup-script bind permits deployment without changing the discovery namespace;
published image bytes remain unchanged. Device traffic and coordinated endpoint
migration are separate acceptance gates, not established by the startup test.
