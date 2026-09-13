# Published server executable URL-string triage

Target: the byte-for-byte reproduced `v1.15.1` Linux amd64 `embedca` server executable (`stunmesh-linux-amd64-ca-v1.15.1`). The binary SHA-256 and source rebuild are recorded in `server-all-platform-release-rebuild.json`.

Method: scan the binary bytes for bounded ASCII `http://` and `https://` substrings, parse plausible hostnames, and manually classify each of the 22 occurrences. This is a static inventory, not a network capture or a claim about dynamically constructed destinations.

| Category | Observed strings | Assessment |
| --- | --- | --- |
| Optional Cloudflare storage | `https://api.cloudflare.com/client/v4` (followed by an unrelated adjacent `opendht` string in the binary) | Matches `internal/plugin/builtin/cloudflare/cloudflare.go`; only used when configured. |
| Go/WireGuard documentation | `go.dev` and `golang.zx2c4.com` references | Documentation/build or error text, not an observed network request. |
| Embedded CA certificate metadata | `crl.d-trust.net`, `www.d-trust.net`, `www.accv.es`, `www.firmaprofesional.com`, `wwww.certigna.fr`, `crl.certigna.fr`, `crl.dhimyotis.com`, `www.cert.fnmt.es`, and `ocsp.accv.es`-like text | CRL/OCSP/CPS/certificate URLs present with the `embedca` root bundle; their presence does not prove the program contacts them. |
| Concatenation false positives | `http://upgradeUpgradechunkedCreatedIM`, `https://mldsa:` and suffix bytes adjoining some valid URLs | Adjacent Go binary strings, not credible hosts or configured destinations. |

No additional obvious telemetry or command-and-control URL appeared in this bounded scan. STUN uses UDP host:port strings, OpenDHT endpoints are configuration values, and code could construct destinations dynamically; absence from this pattern scan is **not** proof that the executable cannot contact an unexpected host. The independently reproduced binary and source-level network surface inventory provide stronger, though still bounded, evidence.
