# STUNMESH Go

This repository contains the STUNMESH Go daemon and mobile core. It uses STUN
and OpenDHT to discover candidate peer endpoints. WireGuard authenticates
peers and encrypts tunnel traffic; discovery hints do not authorize peers or
carry tunnel traffic. Direct connectivity depends on the networks involved.

The Android companion is [stunmesh-android](https://github.com/snf/stunmesh-android).

```sh
go test ./...
CGO_ENABLED=0 go build -tags embedca -o stunmesh-go .
```

The optional container recipe packages only the daemon. WireGuard setup,
peer keys, routing, file synchronization and backups belong in separate
private deployment configuration.

See [the security audit](SECURITY_AUDIT.md) for the historical source review.
