# One-command Android enrollment on the NAS

After installation, run as the existing rootless service user:

```sh
/srv/containers/service-tools/stunmesh-enroll phone --qr
```

Use a distinct device label for each phone. The first invocation creates its
private enrollment; subsequent invocations reopen the same file/QR without
changing keys. `--qr` requires a trusted interactive terminal because the QR
contains a PSK. Without it, output contains paths and instructions only. A
private SVG is also saved for copying over SSH and viewing locally; no HTTP
server or network GUI is opened. Widen the terminal if the QR wraps.

The helper reads the server key/STUN/OpenDHT settings, selects the first unused
phone `/32` in `10.77.0.2–252`, and reserves it against both authorized WG peers
and pending enrollments. Server `.1`, service aliases `.21/.23`, Linux `.253/.254`, and the selected
service-route destinations are excluded. The
site's endpoint and service-only routes come from `enrollment-settings.json`.
Official `wg genpsk` creates a distinct PSK. The phone generates its own private
key after import; the server never generates or imports a phone private key.

Canonical `enrollment.json` is committed automatically to the configured
local-only private Git repository. The SVG is reproducible and ignored by Git.
The command refuses a repository with a remote or unrelated staged changes.
Files are 0600 and device directories 0700. Failure never replaces an existing
enrollment; if Git commit fails after creation, retain the files and fix Git
before retrying. Use a new label for intentional re-enrollment with a new PSK.
Retire/revoke obsolete peers separately.

**A QR is a proposal, not authorization.** Return only the phone's public reply.
Validate it against the original proposal, then explicitly authorize the peer,
its exact `/32` and PSK in the private server configuration and discovery
inventory; include its return route before applying the reviewed VPN-group
update. This helper does not edit/restart live services. New enrollment targets
`stunmesh-enroll-v2`; older discovery namespaces still require the coordinated
[endpoint migration](../../PUBLICATION_TRANSITION.md).

## Installation and confinement

Build/load the dedicated three-executable image, and pin its configuration ID
in the private settings copied from `settings.example.json`. Install
`scripts/stunmesh-enroll` and `scripts/nas_common.py` together in the service-tools
directory. Settings must be owned by the service user, mode 0600. Create the
configured output root as that user, mode 0700; its `.gitignore` contains:

```gitignore
*/enrollment.svg
.enroll-*/
```

Commit the helper, settings and ignore file to the private repository. Supply
working Git author identity there. Keep all actual site settings out of this
public source repository. Do not copy example IP addresses into a live site.

The short-lived rootless container has no network, no capabilities, a read-only
root filesystem, no logs, and bounded memory/process/runtime limits. Generation
mounts server configuration read-only and only its new output directory writable.
QR display mounts only the selected enrollment directory read-only. There is no
new daemon, Go dependency, phone background activity or change to the VPN image.

The image contains static `provision`, official `wg`, and
[libqrencode 4.1.1's CLI](https://github.com/fukuchi/libqrencode/releases/tag/v4.1.1).
QR generation is compiled without PNG support, avoiding libpng/zlib runtime
dependencies; it supports SVG and terminal QR output. The upstream source,
checksum and executable hashes are recorded in `build/enrollment-inputs.json`.
WireGuard source/signature pins remain in `build/inputs.json`. These tools retain
their upstream licenses; use the pinned source and build commands below when
rebuilding or relinking. This is an administrator tool, not part of the always-on
VPN service.

## Rebuild and verify

Fetch the exact QR source URL and verify the SHA-256 in
`build/enrollment-inputs.json`; extract to `stunmesh-build/work/libqrencode-4.1.1`.
Use the existing isolated build environment with networking disabled:

```sh
python3 scripts/sandbox.py -- sh -ec '
  cmake -S /work/libqrencode-4.1.1 -B /work/qrencode-static \
    -DWITHOUT_PNG=ON -DWITH_TESTS=OFF -DBUILD_SHARED_LIBS=OFF \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_EXE_LINKER_FLAGS="-static -s"
  cmake --build /work/qrencode-static -j2
  cp /work/qrencode-static/qrencode /artifacts/qrencode-static
  CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w" \
    -o /artifacts/provision-server ./cmd/provision
'
```

Assemble a new allowlisted context containing only `Dockerfile` from this
folder and the three executables named `provision`, `wg`, `qrencode`. Check their
hashes against the recorded inputs and use `podman build --network=none
--timestamp=0`. No repository-wide COPY or runtime configuration belongs in the
context. Record new pins explicitly after any reviewed rebuild; never substitute
a mutable image tag for the deployment ID.

Checks: Go provisioning/address-allocation tests; Python `test-enrollment.py`,
`test-client.py`, `test-services.py`; actual rootless-container issuance,
idempotency, private Git commits, modes, reservations, remote/TTY rejection,
and independent QR decode against the exact JSON. Use only disposable test
identities. Never print real enrollment data or capture its terminal QR in logs.
