//go:build linux && security_audit

package kernel

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tjjh89017/stunmesh-go/internal/mobilebind"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Compile to a static test binary and run inside the built image's private
// user/network namespace with NET_ADMIN. Never run this on the host network.
// It exercises the real public-only wg CLI metadata, daemon bootstrap, proxy,
// kernel WG and the Android core's actual shared-socket WG bind together.
func TestImageDaemonProxyWithKernelWireGuard(t *testing.T) {
	if os.Getenv("STUNMESH_KERNEL_TEST") != "isolated-image" {
		t.Skip("requires explicit isolated image harness")
	}
	run := func(t *testing.T, name string, args ...string) string {
		t.Helper()
		b, err := exec.Command(name, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s failed: %v", name, err)
		}
		return string(b)
	}
	run(t, "/bin/busybox", "ip", "link", "set", "lo", "up")
	run(t, "/bin/busybox", "ip", "address", "add", "198.51.100.1/32", "dev", "lo")
	for _, mode := range []string{"authorized", "unknown-key", "wrong-psk", "unapproved-source"} {
		t.Run(mode, func(t *testing.T) {
			phone, _ := wgtypes.GeneratePrivateKey()
			server, _ := wgtypes.GeneratePrivateKey()
			serverPublic := server.PublicKey()
			expectedPhone := phone.PublicKey()
			if mode == "unknown-key" {
				other, _ := wgtypes.GeneratePrivateKey()
				expectedPhone = other.PublicKey()
			}
			psk, _ := wgtypes.GenerateKey()
			kernelPSK := psk
			if mode == "wrong-psk" {
				kernelPSK, _ = wgtypes.GenerateKey()
			}
			tun := tuntest.NewChannelTUN()
			client := device.NewDevice(tun.TUN(), mobilebind.New(nil), device.NewLogger(device.LogLevelSilent, ""))
			t.Cleanup(client.Close)
			if err := client.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=51824\npublic_key=%s\npreshared_key=%s\nallowed_ip=10.77.0.1/32\nendpoint=198.51.100.1:51820\n", hex.EncodeToString(phone[:]), hex.EncodeToString(serverPublic[:]), hex.EncodeToString(psk[:]))); err != nil {
				t.Fatal(err)
			}
			if err := client.Up(); err != nil {
				t.Fatal(err)
			}
			run(t, "/bin/busybox", "ip", "link", "add", "wg0", "type", "wireguard")
			t.Cleanup(func() { run(t, "/bin/busybox", "ip", "link", "del", "wg0") })
			dir := t.TempDir()
			cfg := filepath.Join(dir, "wg.conf")
			text := fmt.Sprintf("[Interface]\nPrivateKey = %s\nListenPort = 51822\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = 10.77.0.2/32\n", server.String(), expectedPhone.String(), kernelPSK.String())
			if err := os.WriteFile(cfg, []byte(text), 0600); err != nil {
				t.Fatal(err)
			}
			run(t, "/usr/local/bin/wg", "setconf", "wg0", cfg)
			run(t, "/bin/busybox", "ip", "address", "add", "10.77.0.1/32", "dev", "wg0")
			run(t, "/bin/busybox", "ip", "link", "set", "wg0", "mtu", "1280", "up")
			run(t, "/bin/busybox", "ip", "route", "add", "10.77.0.2/32", "dev", "wg0")
			overlay := filepath.Join(dir, "stunmesh.yml")
			// A local HTTPS fixture stands in for the public proxy. Its CA is
			// trusted only by the child test daemon, never by the host or image.
			envelope, _ := json.Marshal(map[string]string{"magic": "stunmesh-hints-v2", "data": `{"version":2,"ipv4":"198.51.100.1:51824"}`})
			fixture, _ := json.Marshal(map[string]string{"data": base64.StdEncoding.EncodeToString(envelope)})
			dht := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(fixture) }))
			t.Cleanup(dht.Close)
			ca := filepath.Join(dir, "test-ca.pem")
			if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: dht.Certificate().Raw}), 0600); err != nil {
				t.Fatal(err)
			}
			text = fmt.Sprintf("refresh_interval: 180s\ninterfaces:\n  wg0:\n    protocol: ipv4\n    proxy: {listen: 51820}\n    peers:\n      phone:\n        public_key: %s\n        plugin: dht\nplugins:\n  dht:\n    type: builtin\n    name: opendht\n    endpoint: %s\nstun:\n  addresses: [127.0.0.1:9]\nlog: {level: error}\n", expectedPhone.String(), dht.URL)
			if err := os.WriteFile(overlay, []byte(text), 0600); err != nil {
				t.Fatal(err)
			}
			daemon := exec.Command("/usr/local/bin/stunmesh-go", "-c", overlay)
			daemon.Env = append(os.Environ(), "SSL_CERT_FILE="+ca, "SSL_CERT_DIR="+dir)
			if err := daemon.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_ = daemon.Process.Signal(syscall.SIGTERM)
				if err := daemon.Wait(); err != nil {
					t.Error("daemon shutdown failed")
				}
			})
			deadline := time.Now().Add(3 * time.Second)
			for {
				endpoints := run(t, "/usr/local/bin/wg", "show", "wg0", "endpoints")
				if strings.Contains(endpoints, "127.0.0.1:") && !strings.Contains(endpoints, ":51824") {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("daemon did not attach peer to proxy")
				}
				time.Sleep(20 * time.Millisecond)
			}
			source := "10.77.0.2"
			if mode == "unapproved-source" {
				source = "10.77.0.99"
			}
			packet := tuntest.Ping(netip.MustParseAddr("10.77.0.1"), netip.MustParseAddr(source))
			// tuntest only compares payload bytes between fake TUNs. Supply
			// valid IPv4/ICMP checksums for a real kernel protocol stack.
			for _, part := range []struct {
				data   []byte
				offset int
			}{{packet[:20], 10}, {packet[20:], 2}} {
				binary.BigEndian.PutUint16(part.data[part.offset:], 0)
				var sum uint32
				for i := 0; i < len(part.data); i += 2 {
					sum += uint32(binary.BigEndian.Uint16(part.data[i:]))
				}
				for sum>>16 != 0 {
					sum = (sum & 0xffff) + (sum >> 16)
				}
				binary.BigEndian.PutUint16(part.data[part.offset:], ^uint16(sum))
			}
			select {
			case tun.Outbound <- packet:
			case <-time.After(time.Second):
				t.Fatal("client stalled")
			}
			select {
			case response := <-tun.Inbound:
				if mode != "authorized" {
					t.Fatal("kernel accepted unauthorized traffic")
				}
				if len(response) < 28 || response[20] != 0 || !bytes.Equal(response[12:16], []byte{10, 77, 0, 1}) {
					t.Fatal("not a kernel ICMP echo reply")
				}
			case <-time.After(2 * time.Second):
				if mode == "authorized" {
					for _, field := range []string{"latest-handshakes", "transfer", "endpoints"} {
						t.Log(field, run(t, "/usr/local/bin/wg", "show", "wg0", field))
					}
					t.Fatal("no authenticated kernel reply through daemon proxy")
				}
			}
		})
	}
}
