package wg

import (
	"context"
	"errors"
	"net"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type fakeWgctrlBackend struct {
	deviceFn          func(name string) (*wgtypes.Device, error)
	configureDeviceFn func(name string, cfg wgtypes.Config) error

	configuredName string
	configuredCfg  wgtypes.Config
}

func (f *fakeWgctrlBackend) Device(name string) (*wgtypes.Device, error) {
	return f.deviceFn(name)
}

func (f *fakeWgctrlBackend) ConfigureDevice(name string, cfg wgtypes.Config) error {
	f.configuredName = name
	f.configuredCfg = cfg
	return f.configureDeviceFn(name, cfg)
}

func (f *fakeWgctrlBackend) Close() error {
	return nil
}

func TestCtrlClient_UpdatePeerEndpoint_ConfiguresDevice(t *testing.T) {
	var pk Key
	copy(pk[:], bytes32(0x07))

	backend := &fakeWgctrlBackend{
		configureDeviceFn: func(name string, cfg wgtypes.Config) error {
			return nil
		},
	}
	c := &ctrlClient{c: backend}

	err := c.UpdatePeerEndpoint(context.Background(), PeerEndpointUpdate{
		DeviceName: "testdev",
		PublicKey:  pk,
		Host:       "1.2.3.4",
		Port:       5678,
	})
	if err != nil {
		t.Fatalf("UpdatePeerEndpoint: unexpected error: %v", err)
	}

	if backend.configuredName != "testdev" {
		t.Errorf("configured device name = %q, want %q", backend.configuredName, "testdev")
	}
	if len(backend.configuredCfg.Peers) != 1 {
		t.Fatalf("configured peers len = %d, want 1", len(backend.configuredCfg.Peers))
	}
	peerCfg := backend.configuredCfg.Peers[0]
	if peerCfg.PublicKey != wgtypes.Key(pk) {
		t.Errorf("configured peer public key mismatch")
	}
	if peerCfg.UpdateOnly != UpdateOnly {
		t.Errorf("UpdateOnly = %v, want %v (package constant)", peerCfg.UpdateOnly, UpdateOnly)
	}
	wantEndpoint := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 5678}
	if peerCfg.Endpoint == nil || !peerCfg.Endpoint.IP.Equal(wantEndpoint.IP) || peerCfg.Endpoint.Port != wantEndpoint.Port {
		t.Errorf("configured peer endpoint = %v, want %v", peerCfg.Endpoint, wantEndpoint)
	}
}

func TestCtrlClient_UpdatePeerEndpoint_ErrorPassesThroughElevationHint(t *testing.T) {
	backendErr := errors.New("configure failed")
	backend := &fakeWgctrlBackend{
		configureDeviceFn: func(name string, cfg wgtypes.Config) error {
			return backendErr
		},
	}
	c := &ctrlClient{c: backend}

	err := c.UpdatePeerEndpoint(context.Background(), PeerEndpointUpdate{DeviceName: "testdev", Host: "192.0.2.1", Port: 51820})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, backendErr) {
		t.Errorf("UpdatePeerEndpoint error = %v, want it to wrap %v", err, backendErr)
	}
	if errors.Is(err, ErrElevationRequired) {
		t.Errorf("ordinary error must not be marked ErrElevationRequired")
	}
}

func bytes32(b byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = b
	}
	return out
}
