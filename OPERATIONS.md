# Deployment boundaries

This public repository contains software and generic deployment examples. Private production inventories, device captures, account names, enrollment records and operational history are retained outside public Git. Do not treat example IP addresses, aliases or directories as a live installation's settings.

- Run the NAS service with rootless Podman under the chosen service user. Preserve ownership, UID/GID mappings, read-only configuration mounts and the documented capability limits. See [deploy/README.md](deploy/README.md).
- Configure only the selected service routes. The development profile uses a narrow fixed address policy; changing the site layout requires reviewing the validator and its tests. It is not a general-purpose default-route VPN.
- The optional [direct-host Linux client](deploy/client-host/README.md) needs privileged network operations inside its isolated deployment. The simpler [rootless client](deploy/client/README.md) has different host-access limitations.
- Review every example endpoint, host binding, account and path before use. Supply confidential peer profiles through private files. Keep private deployment configuration under an appropriate private backup/version-control policy, never this public remote.
- Start service groups only after the encrypted data volume is mounted and the startup checks pass. Preserve existing file-sharing services and firewall policy unless a separate reviewed deployment change calls for modifications. Restic remains disabled until directories, credentials and retention are chosen.
- Provisioning must write exclusive mode-0600 files and disable helper-container logging. Affected credentials from older logged provisioning or diagnostic output must be rotated, including consumers; deleting logs alone does not restore trust.

Publishing this repository does not enroll peers, install a client, alter a NAS, rotate live credentials or enable backup. Complete the [device/service acceptance plan](DEVICE_TESTS.md) for the actual environment. The [release guide](RELEASES.md) identifies the verified container and companion Android APK.
