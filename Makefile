# Use the pinned toolchain, normally through scripts/sandbox.py. No installer,
# release uploader, process plugins or automatic toolchain downloads.
APP_VERSION ?= local
.PHONY: build test vet core provision
build:
	CGO_ENABLED=0 go build -mod=readonly -trimpath -buildvcs=false -tags embedca -ldflags '-s -w -X main.buildVersion=$(APP_VERSION)' -o /artifacts/stunmesh-go .
provision:
	CGO_ENABLED=0 go build -mod=readonly -trimpath -buildvcs=false -ldflags '-s -w' -o /artifacts/provision ./cmd/provision
core:
	cd mobile && gomobile bind -target=android/arm64,android/amd64 -androidapi 28 -tags mobile -trimpath -ldflags '-s -w -X github.com/tjjh89017/stunmesh-go/mobile.version=$(APP_VERSION) -extldflags=-Wl,-z,max-page-size=16384' -o /artifacts/stunmesh-core.aar .
test:
	go test -race -tags 'mobile security_audit' ./...
vet:
	go vet -tags 'mobile security_audit' ./...
