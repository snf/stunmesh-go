# Syncthing VPN-only preparation

- [x] Replace direct LAN publication/TCP forwarding with an exact VPN listener
  in the existing rootless VPN namespace; publish no host sync or GUI ports.
- [x] Disable client sync listeners, discovery, relays, NAT traversal, QUIC,
  reporting and automatic core upgrades; clients initiate only to the NAS.
- [x] Keep native device TLS authentication and explicit folder membership.
- [x] Replace fixed three-device/folder templates with reviewed inventories;
  preserve existing identities and folder versioning when adding peers.
- [x] Preserve large-volume identity checks and rootless ownership constraints.
- [x] Add a client namespace unreachable route and refuse an underlay route.
- [x] Run 21 helper regression tests plus actual pinned-container tests using
  four disposable identities and synthetic data on the mounted large volume.
- [x] Native bidirectional transfer and client restart pass. No host ports, GUI,
  wildcard sync or local-discovery listeners; file ownership preserved.
- [x] Native route lookup fails after removal of the guarded WG interface.
- [ ] Owner-generated production IDs, actual folder/mount approval and activation.
- [ ] Apply and verify the Android/laptop app settings on the actual devices.
- [ ] Resolve Android no-underlay enforcement when the VPN disappears; a private
  destination and disabled discovery are not an OS per-app kill switch.
- [ ] Real-device synchronization, external VPN discovery migration and later
  iPhone client/background-behavior acceptance.

The native fixture joined an isolated namespace with a WG interface/address; its
successful file transfer does not establish traffic through a real remote WG
peer. No production phone, laptop, cloud data or real sync directory was used.
An initial loopback-listener fixture exposed outgoing loopback source reuse;
removing unnecessary client listeners fixed it and reduced the listening surface.

No new host dependency, firewall rule, timer or phone background job was added.
Existing Python administration wrappers remain a documented separate boundary.
Private deployment details and actual identities belong only in local site Git.
