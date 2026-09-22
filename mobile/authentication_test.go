//go:build mobile && (linux || android)

package mobile

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tjjh89017/stunmesh-go/internal/mobilebind"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Real WireGuard devices and the shipped shared UDP bind, not a mock authenticator.
// All identities are generated for the test and remain inside its isolated netns.
func TestWireGuardAloneAuthorizesDecryption(t *testing.T) {
	for _, mode := range []string{"authorized", "unknown-key", "wrong-psk", "unapproved-source"} {
		t.Run(mode, func(t *testing.T) {
			a, _ := wgtypes.GeneratePrivateKey()
			b, _ := wgtypes.GeneratePrivateKey()
			rogue, _ := wgtypes.GeneratePrivateKey()
			psk, _ := wgtypes.GenerateKey()
			expected := a.PublicKey()
			serverPSK := psk
			if mode == "unknown-key" {
				expected = rogue.PublicKey()
			}
			if mode == "wrong-psk" {
				serverPSK, _ = wgtypes.GenerateKey()
			}
			ta, tb := tuntest.NewChannelTUN(), tuntest.NewChannelTUN()
			da := device.NewDevice(ta.TUN(), mobilebind.New(nil), device.NewLogger(device.LogLevelSilent, ""))
			db := device.NewDevice(tb.TUN(), mobilebind.New(nil), device.NewLogger(device.LogLevelSilent, ""))
			t.Cleanup(da.Close)
			t.Cleanup(db.Close)
			configure := func(d *device.Device, private, peer, shared wgtypes.Key, route string) {
				t.Helper()
				err := d.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=0\npublic_key=%s\npreshared_key=%s\nallowed_ip=%s\n", hex.EncodeToString(private[:]), hex.EncodeToString(peer[:]), hex.EncodeToString(shared[:]), route))
				if err != nil {
					t.Fatal("synthetic WG configuration rejected")
				}
				if err = d.Up(); err != nil {
					t.Fatal(err)
				}
			}
			configure(da, a, b.PublicKey(), psk, "10.77.0.1/32")
			configure(db, b, expected, serverPSK, "10.77.0.2/32")
			status, err := db.IpcGet()
			if err != nil {
				t.Fatal("WG status unavailable")
			}
			port := ""
			for _, line := range strings.Split(status, "\n") {
				if strings.HasPrefix(line, "listen_port=") {
					port = strings.TrimPrefix(line, "listen_port=")
				}
			}
			if n, _ := strconv.Atoi(port); n == 0 {
				t.Fatal("no listening socket")
			}
			n := &Node{dev: da, running: true, cfg: &tunnelConfig{Peers: []peerConfig{{PublicKey: b.PublicKey().String()}}}, listener: noopListener{}}
			if err = n.SetPeerEndpoint(b.PublicKey().String(), "127.0.0.1:"+port); err != nil {
				t.Fatal(err)
			}
			source := "10.77.0.2"
			if mode == "unapproved-source" {
				source = "10.77.0.99"
			}
			packet := tuntest.Ping(netip.MustParseAddr("10.77.0.1"), netip.MustParseAddr(source))
			select {
			case ta.Outbound <- packet:
			case <-time.After(2 * time.Second):
				t.Fatal("WG did not consume test packet")
			}
			select {
			case got := <-tb.Inbound:
				if mode != "authorized" {
					t.Fatal("unauthorized plaintext reached receiving TUN")
				}
				if !bytes.Equal(got, packet) {
					t.Fatal("payload changed")
				}
			case <-time.After(time.Second):
				if mode == "authorized" {
					t.Fatal("authorized handshake/data transfer failed")
				}
			}
			if mode == "authorized" {
				// No discovery key can replace this authorization. Offline closes sockets;
				// resuming reuses the approved peer identity and can bind a new underlay.
				n.network = underlayState{online: true, ipv4: true}
				if err = n.SetUnderlay(false, false, false, false); err != nil {
					t.Fatal(err)
				}
				if err = n.SetUnderlay(true, true, false, true); err != nil {
					t.Fatal(err)
				}
				select {
				case ta.Outbound <- packet:
				case <-time.After(time.Second):
					t.Fatal("resume stalled")
				}
				select {
				case got := <-tb.Inbound:
					if !bytes.Equal(got, packet) {
						t.Fatal("resume changed data")
					}
				case <-time.After(8 * time.Second):
					t.Fatal("resume did not recover")
				}
			}
		})
	}
}

type noopListener struct{}

func (noopListener) OnStateChanged(string)          {}
func (noopListener) OnLog(string, string)           {}
func (noopListener) OnEvent(string, string, string) {}

func TestUnderlayEventsCancelAndCoalesce(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	c := &controller{cycleCancel: cancel, changed: make(chan struct{}, 1)}
	for i := 0; i < 100; i++ {
		c.networkChanged(underlayState{})
	}
	select {
	case <-ctx.Done():
	default:
		t.Fatal("inflight request not cancelled")
	}
	if len(c.changed) != 1 {
		t.Fatal("underlay burst queued redundant work")
	}
	disc := &fakeDiscoverer{}
	offline := newDiscoverTestController("dualstack", disc, &fakeListener{})
	offline.network = underlayState{}
	if _, err := offline.discover(context.Background()); err == nil {
		t.Fatal("offline discovery succeeded")
	}
	if len(disc.probed) != 0 {
		t.Fatal("offline discovery emitted packets")
	}
}
