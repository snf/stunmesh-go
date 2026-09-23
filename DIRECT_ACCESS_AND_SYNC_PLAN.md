# Direct access and synchronization

Use native WireGuard for peer authentication and destination-based split routing. Keep NAS services containerized, private configuration mounted from outside the public repository, and file ownership/UID mappings explicit. Syncthing and selected file-sharing endpoints belong on the LAN or authorized tunnel routes. Restic remains disabled until backup scope is selected.

Host-specific names, topology, data directories and enrollment decisions are retained privately. Public examples require site-specific review; see [OPERATIONS.md](OPERATIONS.md), [direct-client instructions](deploy/client-host/README.md), [release guide](RELEASES.md) and [acceptance tests](DEVICE_TESTS.md).
