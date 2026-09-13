# Direct Go dependency triage at the audited source pin

This maps the 14 direct `go.mod` requirements at commit
`71a73228cd2bc001cdc5d485a16621a24bfae15a`. The file also declares 16
indirect requirements. `go list -m all` resolves 58 external modules; the
published Linux amd64 regular executable embeds 19 dependency modules in its
Go build information, and the all-builtins Android AAR embeds 15 dependency
modules plus the main module. “Present” below means named in that build
information, not that every package/function was linked or executed. Versions
without a stable release number are shown by their pinned commit suffix; the
full pseudo-versions are in `go.mod`.

| Direct module (pinned version) | Why it is present | Linux amd64 regular | Android all-builtins AAR | Audit judgment for a minimal home build |
| --- | --- | --- | --- | --- |
| `github.com/go-viper/mapstructure/v2` `v2.5.0` | Desktop config mapping; shared import graph reaches mobile. | Present | Present | G-13 found a malformed-key panic at its input boundary. Validate keys; separate desktop config from mobile. |
| `github.com/google/wire` `v0.7.0` | Dependency-injection wiring in shared packages. | Present | Present | Generated wiring is a convenience, not a VPN primitive; a mobile-specific graph could drop it. |
| `github.com/packetcap/go-pcap` `f2cf9f991e7c` | Darwin/BSD packet capture for STUN. | Absent | Absent | Niche platform dependency; no need in Linux NAS or Android artifact. Its complete source was not audited. |
| `github.com/pion/stun/v3` `v3.1.7` | Desktop STUN codec/client. | Present | Absent | Pion is the declared STUN source; Android uses its own shared-socket STUN code, reviewed separately. |
| `github.com/rs/zerolog` `v1.35.1` | Structured logs. | Present | Present | Review call sites for credential logging; G-17 found an app-layer URL leak, not a zerolog compromise. |
| `go.uber.org/mock` `v0.6.0` | Test/mock generation. | Absent | Absent | Development-only; do not include mock generators in runtime images. |
| `go.yaml.in/yaml/v3` `v3.0.5` | Desktop YAML config; shared graph also reaches mobile. | Present | Present | Mobile imports JSON from Kotlin, so split away the YAML loader after G-13 is fixed. |
| `golang.org/x/crypto` `v0.55.0` | NaCl discovery box and other crypto utilities. | Present | Present | G-02 policy mismatch and G-14 low-order point matter more than an OSV module-level hit; remove box if WireGuard-only discovery is chosen. |
| `golang.org/x/crypto/x509roots/fallback` `d701c51f7e4e` | Optional embedded CA trust roots under `embedca`. | Absent | Absent | Present in the separate CA-embedded server variants. Use a reviewed base-image CA store for the home build if operationally suitable. |
| `golang.org/x/mobile` `6129f5bee9d5` | `gomobile` binding tool requirement. | Absent | Absent | Build-time only; pin the tool and keep it out of runtime images. |
| `golang.org/x/net` `v0.58.0` | Shared network/DNS support. | Present | Present | Keep only while its used packages remain necessary; checksum and advisory scan completed. |
| `golang.org/x/sys` `v0.47.0` | OS socket, routing and platform calls. | Present | Present | Required by the current architecture; inspect privilege and socket call sites. |
| `golang.zx2c4.com/wireguard` `f333402bd9cb` | Embedded wireguard-go packet engine on Android. | Absent | Present | Essential on Android, absent from the Linux desktop daemon; update and retest the pinned upstream delta. |
| `golang.zx2c4.com/wireguard/wgctrl` `a9ab2273dd10` | Desktop control of an existing WG interface. | Present | Present | Essential for the selected Linux backend, but its appearance in the Android AAR reflects an avoidable shared-package import. |

All fetched module ZIP and `go.mod` hashes matched `sum.golang.org`, and
`go mod verify` passed (`go-sumdb-comparison.json`, `go-mod-verify.txt`). The
16 reproduced server executable payloads and the independent AAR comparison in the main
report further test build-output correspondence. These checks detect changes
relative to published artifacts and source, but **cannot prove** that an
upstream author, dependency account or release process was not compromised.
No downloaded module was classified as malicious in this audit.

For the actual NAS/phone fork, retain only OpenDHT as the compiled built-in,
remove the optional executable/shell plugin constructors, pin exact module and
toolchain versions, and separate mobile source from desktop YAML/wgctrl code.
The current `builtin_opendht,mobile` build did remove Cloudflare's code and
URL, but still linked the generic process-plugin manager. Do not claim that
build tags alone make the AAR minimal.
