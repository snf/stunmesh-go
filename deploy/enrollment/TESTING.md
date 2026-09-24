# Check an enrolled Android phone

No USB, ADB, root, extra monitoring service or battery-policy change is needed
for these checks. Use the release app and a client for an existing SSH or SMB
service. Addresses below are examples; use the routes in your actual enrollment.

## Finish enrollment first

1. Import the private enrollment QR/file and create the phone identity.
2. Tap **Copy public reply** and return that reply to the administrator over a
   trusted channel. It contains a public key, proposal ID and phone address, not
   the phone private key or PSK. Do not send the QR/enrollment file: it carries
   the PSK. Independently confirm that the reply belongs to the intended phone.
3. The administrator validates the reply against the saved proposal, authorizes
   its exact public key/address/PSK in WireGuard and the discovery inventory,
   adds its return route, and applies the reviewed VPN/forwarder group update.
   QR generation does none of these live operations. Do not repeatedly generate
   new identities while diagnosing an unapproved peer.
4. Confirm compatible server/phone discovery builds. A direct LAN handshake can
   work even when incompatible discovery namespaces prevent external access.
   Follow the [publication transition](../../PUBLICATION_TRANSITION.md), including
   existing laptop clients; do not upgrade the server alone without reviewing them.

## Home Wi-Fi

1. Pause any other VPN in the same Android profile. Leave **Block connections
   without VPN** off. Check that STUNMESH lists only selected server destinations
   (for example `10.77.0.1/32`), without a default route or VPN DNS override.
2. Tap **Review & connect**, confirm the profile and accept Android's VPN prompt.
3. In an existing SMB client, connect to the server's **VPN IP**, for example
   `smb://10.77.0.1` on TCP 445, using its normal Samba account. List a permitted
   share and read an existing non-sensitive file. Alternatively, connect an SSH
   client to that VPN IP on port 22 and verify the host key through the existing
   trusted LAN administration path before accepting it.
4. Look for **Authenticated session observed** in STUNMESH with a time from this
   session. Combine it with successful service traffic: an old handshake or the
   Android VPN icon alone is insufficient. Open an ordinary HTTPS website too.
5. Stop STUNMESH, close the service connection and try a **new** connection to
   that same VPN IP. It should fail while ordinary internet still works. Start
   STUNMESH and reconnect successfully. This control helps establish that the
   service used the VPN rather than a cached connection or LAN hostname.

Do not use a LAN IP, automatic LAN discovery or a hostname resolving to the LAN
IP as evidence of VPN access. Destination routing applies to every app reaching
the selected IPs, not only the app used for this test. Opening a website alone
does not prove internet bypass: also verify the narrow route list and absence
of a VPN DNS/default route. More detailed routing checks are in
[DEVICE_TESTS.md](../../DEVICE_TESTS.md).

## Away from home and return

Keep STUNMESH running. Disable home Wi-Fi and use mobile data, or connect to a
second phone's hotspot whose uplink is mobile data (its home Wi-Fi must be off).
Repeat both the ordinary website and VPN-IP service tests. Note the elapsed
time after the new internet connection works; discovery can take multiple cycles.
If no connection appears after about three minutes, record the network, elapsed
time and last authenticated-session time for diagnosis. This is a diagnostic
checkpoint, not a promised recovery time or proof that every NAT is supported.

Return to home Wi-Fi without restarting STUNMESH and repeat the service test.
Record recovery time. A short screen-lock/background check can follow; longer
battery/endurance tests remain a separate acceptance stage. No relay fallback
exists, so passing one external network does not guarantee all networks.

## Server-side confirmation (read-only)

Run as the rootless service user. Substitute the actual VPN container name:

```sh
podman exec VPN_CONTAINER /usr/local/bin/wg show wg0 allowed-ips
podman exec VPN_CONTAINER /usr/local/bin/wg show wg0 latest-handshakes
podman exec VPN_CONTAINER /usr/local/bin/wg show wg0 transfer
```

Match the public key from the phone reply to its exact `/32`. A nonzero recent
handshake and increasing receive/transmit counters while testing that peer,
together with the real service response, demonstrate authenticated traffic.
These selected queries do not output private keys or PSKs. Do not replace them
with `wg showconf`, `wg show ... dump`, full container inspection or raw configs.

An absent peer means authorization is incomplete. Handshake zero means no
successful handshake since interface creation. A handshake with failing service
traffic calls for checking return routes, forwarders, destination service and
service credentials, not weakening authentication. A listening Syncthing
forwarder alone does not mean Syncthing is running behind it. Historical test
HTTP URLs work only while their explicitly prepared temporary fixture is active.

Keep site-specific results in private deployment Git: app/image versions,
pass/fail/blocked, network type and observed timing. Never include private
enrollment contents, QR screenshots or secret-bearing diagnostics in public Git.
