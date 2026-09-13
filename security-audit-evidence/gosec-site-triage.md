# Per-site triage of 21 gosec findings

Audited Go production source at `71a73228cd2bc001cdc5d485a16621a24bfae15a`; gosec v2.29.0 summary is in `gosec-core-summary.json`. This is source/control-flow triage, not proof that a future configuration or platform cannot violate the observed bounds.

| Rule and site | Data and consequence | Disposition |
| --- | --- | --- |
| G115 `internal/mobilebind/bind.go:92` | Kernel file descriptor `uintptr` to Android protector `int32` callback. | POSIX descriptors are 32-bit signed handles in this path; no untrusted numeric input reaches it. |
| G115 `internal/wgproxy/proxy.go:173` | `uint32` atomic WireGuard target port to `uint16`. | `SetWGTarget` accepts only `uint16`, so the stored value is already bounded. |
| G115 `internal/plugin/dialer/dialer.go:214` | `len(servers)` to `uint32` for rotation. | A slice over 2^32 entries is infeasible in the supported process address space; no network-sized integer feeds this cast. |
| G115 `internal/wgproxy/proxy.go:152` | Bound UDP socket's OS-returned port `int` to `uint16`. | UDP port is already in 0–65535. |
| G115 `internal/wg/proxy_client.go:101` | Selected peer endpoint `int` to `uint16` in proxy mode. | **Actionable G-10:** the selected decrypted hint's port is not checked to be 1–65535; out-of-range values can wrap and change the destination. It does not add a WireGuard peer. |
| G115 `internal/wg/proxy_client.go:72` | Existing WireGuard device's listen port `int` to `uint16`. | OS/WireGuard device state supplies a valid UDP port; a malicious fake backend is outside production. |
| G115 `internal/stun/helper_socket.go:77` | Constructed STUN binding packet length to `uint16`. | Fixed-size 20-byte STUN request plus fixed UDP header, far below 65536. |
| G115 `internal/mobilebind/bind.go:65` | Bound socket's OS-returned port `int` to `uint16`. | UDP port is already in 0–65535. |
| G115 `internal/ctrl/publish.go:73` | Existing WireGuard device's listen port `int` to `uint16`. | OS/WireGuard device state supplies a valid UDP port. |
| G115 `internal/ctrl/ping_monitor.go:459` | Parsed ICMP Echo ID `int` to `uint16`. | The wire format allocates exactly 16 bits for the ID. Health signaling is not peer authentication. |
| G115 `internal/ctrl/ping_monitor.go:231` | `rand.Intn(65535)+1` to `uint16`. | Explicit range is 1–65535. RNG quality is separately flagged below. |
| G115 `internal/config/device.go:141` | Local `proxy.listen` `int` to `uint16`. | `config.validate` rejects values outside 0–65535 before device configuration (`config.go:290–291`). |
| G115 `mobile/node.go:76` | JSON MTU `int` to `int32` before Android TUN creation. | Android's `TunnelConfig` stores MTU as Kotlin `Int` (already signed 32-bit), so its ordinary bridge cannot overflow this cast. The Go API alone accepts arbitrary JSON and should still enforce a sensible MTU range; a malformed local caller may cause startup failure. |
| G404 `internal/ctrl/ping_monitor.go:231` | `math/rand` chooses a 16-bit ICMP health-check ID. | This is not a WireGuard key or authenticator. The monitor also checks source target IP, but a tunnel/underlay actor able to spoof that source may forge health replies more easily than with an unpredictable ID. Use `crypto/rand` and validate Echo sequence/payload if health is used for critical automation. Conditional availability hardening, not a demonstrated remote entry path. |
| G401 `internal/entity/peer_id.go:34` | SHA-1 over ordered public-key pair. | Public DHT index; not a signature, MAC, or password hash. Collision/poisoning affects availability, already handled as G-03. |
| G401 `internal/entity/peer_id.go:43` | Same SHA-1 for reverse key order. | Same public-index disposition; reflection is separately G-02. |
| G505 `internal/entity/peer_id.go:4` | Import of `crypto/sha1`. | Same public-index disposition. |
| G114 `test/e2e/realnet/canary/main.go:46–48` | Test-only fixed-blob HTTP server has no timeouts. | Not linked into the daemon, AAR, or published container; relevant only to isolated e2e test resource use. |
| G204 `internal/plugin/shell.go:82` | Configured command executed as a subprocess. | Deliberate optional plugin surface, G-06. Requires local config/import choice; not a DHT-supplied command. |
| G204 `internal/plugin/exec.go:84` | Configured command executed as a subprocess. | Same G-06 disposition; remove from the minimal home build. |
| G304 `internal/config/config.go:195` | Reads path selected by `-c` or default local config search. | Intentional local file access, not a remote path. The malformed YAML panic on that path is G-13. |

The scanner omitted the high-impact Android mobile-core UAPI injection (G-01). The table distinguishes reported issues from false-positive preconditions; it does not replace the integration tests or source review.
