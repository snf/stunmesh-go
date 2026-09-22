package wg

import (
	"context"
	"net/netip"
	"testing"

	"github.com/tjjh89017/stunmesh-go/internal/wgproxy"
)

// The desktop controller uses strconv.Atoi on a decrypted endpoint port;
// proxy mode later narrows that int to uint16 without a range check.
// A malformed authenticated record can therefore select a different port.
func TestSecurityProxyRejectsOutOfRangeDiscoveredPort(t *testing.T) {
	peer := testKey(0xA7)
	inner := &fakeClient{device: &DeviceInfo{Name: "wg0", ListenPort: 51820, PeerKeys: []Key{peer}}}
	pc, manager := newTestProxyClient(t, inner, &fakeProxyConfig{protocol: "ipv4"})
	if _, err := pc.Device(context.Background(), "wg0"); err != nil {
		t.Fatal(err)
	}
	if err := pc.UpdatePeerEndpoint(context.Background(), PeerEndpointUpdate{
		DeviceName: "wg0", PublicKey: peer, Host: "203.0.113.9", Port: 65537,
	}); err == nil {
		t.Fatal("accepted out-of-range discovered port")
	}
	proxy, err := manager.For("wg0", nil)
	if err != nil {
		t.Fatal(err)
	}
	decision := proxy.Demux().Classify(netip.MustParseAddrPort("203.0.113.9:1"), []byte{4, 0, 0, 0})
	if decision.Bucket == wgproxy.BucketRelay {
		t.Fatalf("invalid update changed relay mapping: %+v", decision)
	}
}
