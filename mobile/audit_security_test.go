//go:build mobile && security_audit && (linux || android)

package mobile

// These tests demonstrate baseline security behavior; passing does not mean
// the behavior is safe. They use fresh synthetic keys and an in-memory TUN.
// Run in a network-isolated environment. No NAS configuration is consumed.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	smcrypto "github.com/tjjh89017/stunmesh-go/internal/crypto"
	"github.com/tjjh89017/stunmesh-go/internal/ctrl"
	"github.com/tjjh89017/stunmesh-go/internal/entity"
	"github.com/tjjh89017/stunmesh-go/internal/mobilebind"
	"github.com/tjjh89017/stunmesh-go/internal/plugin"
	"github.com/tjjh89017/stunmesh-go/internal/plugin/registry"
	pluginapi "github.com/tjjh89017/stunmesh-go/pluginapi"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type auditRecordStore struct {
	key, value string
}

// The Android app documents "built-in plugins only", but JSON crosses the
// gomobile boundary into the shared manager without an allowlist. In a Linux
// mobile-core build the same path runs a local command. This verifies the
// admission bug; an Android OS process execution is tested separately.
func TestAuditMobileCoreAcceptsExecutablePlugin(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "marker")
	script := filepath.Join(dir, "plugin.sh")
	body := "#!/bin/sh\nprintf reached > " + marker + "\ncat >/dev/null\nprintf '{\"success\":true,\"value\":\"ok\"}\\n'\n"
	if err := os.WriteFile(script, []byte(body), 0700); err != nil {
		t.Fatal(err)
	}
	raw := `{"interface":{"private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},"plugins":[{"instance":"p","type":"exec","name":"ignored","config":{"command":"` + script + `"}}]}`
	cfg, err := parseConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	defs := map[string]pluginapi.PluginDefinition{
		"p": {Type: cfg.Plugins[0].Type, Config: pluginapi.PluginConfig{
			"command": script,
		}},
	}
	manager := plugin.NewManager()
	if err := manager.LoadPlugins(context.Background(), defs); err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	store, err := manager.GetPlugin("p")
	if err != nil {
		t.Fatal(err)
	}
	value, err := store.Get(context.Background(), "synthetic-key")
	if err != nil {
		t.Fatal(err)
	}
	if value != "ok" {
		t.Fatalf("unexpected fixture response %q", value)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("exec plugin did not run local script:", err)
	}
	t.Log("DEMONSTRATED: mobile JSON accepted an exec plugin and the shared plugin manager executed its command")
}

func (s *auditRecordStore) Get(_ context.Context, key string) (string, error) {
	if key != s.key {
		return "", fmt.Errorf("unexpected synthetic lookup key")
	}
	return s.value, nil
}
func (s *auditRecordStore) Set(context.Context, string, string) error { return nil }

func init() {
	registry.Register("audit_static_record", func(c pluginapi.PluginConfig) (pluginapi.Store, error) {
		return &auditRecordStore{key: c["key"].(string), value: c["value"].(string)}, nil
	})
}

func auditKey(t *testing.T) wgtypes.Key {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func auditHex(k wgtypes.Key) string { return hex.EncodeToString(k[:]) }

// A discovery peer possessing its static private key can add an entirely
// different peer through an endpoint record, without knowing the WG PSK and
// without completing a WireGuard handshake.
func TestAuditDiscoveryRecordCanEnrollPeer(t *testing.T) {
	for _, authenticated := range []bool{false, true} {
		t.Run(fmt.Sprintf("correct_discovery_signer_%t", authenticated), func(t *testing.T) {
			local, legitimate, rogue, outsider := auditKey(t), auditKey(t), auditKey(t), auditKey(t)
			psk := auditKey(t)
			cfg := &tunnelConfig{
				Interface: ifaceConfig{PrivateKey: local.String(), MTU: 1420},
				Peers: []peerConfig{{
					Name: "legitimate", PublicKey: legitimate.PublicKey().String(),
					PresharedKey: psk.String(), AllowedIPs: []string{"10.89.0.2/32"},
					Plugin: "fixture", Protocol: "ipv4",
				}},
			}
			// No actual system TUN device or privileged WireGuard interface.
			ct := tuntest.NewChannelTUN()
			bind := mobilebind.New(nil)
			dev := device.NewDevice(ct.TUN(), bind, device.NewLogger(device.LogLevelSilent, ""))
			defer dev.Close()
			uapi, err := buildUAPI(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err := dev.IpcSet(uapi); err != nil {
				t.Fatal(err)
			}
			if err := dev.Up(); err != nil {
				t.Fatal(err)
			}
			n := &Node{cfg: cfg, dev: dev, bind: bind, running: true, listener: &fakeListener{}}
			c, err := newController(n, bind)
			if err != nil {
				t.Fatal(err)
			}
			defer c.manager.Close()
			roguePub := rogue.PublicKey()
			localPub, legitimatePub := local.PublicKey(), legitimate.PublicKey()
			reservation, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			roguePort := reservation.LocalAddr().(*net.UDPAddr).Port
			if err := reservation.Close(); err != nil {
				t.Fatal(err)
			}
			var rogueTun *tuntest.ChannelTUN
			if authenticated {
				rogueTun = tuntest.NewChannelTUN()
				rogueDev := device.NewDevice(rogueTun.TUN(), mobilebind.New(nil), device.NewLogger(device.LogLevelSilent, ""))
				defer rogueDev.Close()
				rogueUAPI := fmt.Sprintf("private_key=%s\nlisten_port=%d\npublic_key=%s\nallowed_ip=10.89.0.1/32\n",
					auditHex(rogue), roguePort, auditHex(localPub))
				if err := rogueDev.IpcSet(rogueUAPI); err != nil {
					t.Fatal(err)
				}
				if err := rogueDev.Up(); err != nil {
					t.Fatal(err)
				}
			}
			payload := "127.0.0.1:9\npreshared_key=" + strings.Repeat("0", 64) +
				"\npublic_key=" + auditHex(roguePub) + "\nallowed_ip=10.89.0.2/32" +
				fmt.Sprintf("\nendpoint=127.0.0.1:%d", roguePort)
			plain, err := json.Marshal(ctrl.EndpointData{IPv4: payload})
			if err != nil {
				t.Fatal(err)
			}
			signer := outsider
			if authenticated {
				signer = legitimate
			}
			encrypted, err := smcrypto.NewEndpoint().Encrypt(context.Background(), &ctrl.EndpointEncryptRequest{
				PeerPublicKey: entity.PeerPublicKey(local.PublicKey()),
				PrivateKey: entity.PrivateKey(signer),
				Content: string(plain),
			})
			if err != nil {
				t.Fatal(err)
			}
			id := entity.NewPeerId(localPub[:], legitimatePub[:])
			err = c.manager.LoadPlugins(context.Background(), map[string]pluginapi.PluginDefinition{
				"fixture": {Type: "builtin", Config: pluginapi.PluginConfig{
					"name": "audit_static_record", "key": id.RemoteEndpointKey(), "value": encrypted.Data,
				}},
			})
			if err != nil {
				t.Fatal(err)
			}
			before, err := dev.IpcGet()
			if err != nil {
				t.Fatal(err)
			}
			c.establish(context.Background(), nil)
			after, err := dev.IpcGet()
			if err != nil {
				t.Fatal(err)
			}
			if !authenticated {
				if before != after {
					t.Fatal("negative control: wrong discovery signer changed WG state")
				}
				t.Log("wrong discovery signer rejected; no peer configuration change")
				return
			}
			if !strings.Contains(after, "public_key="+auditHex(roguePub)+"\n") {
				t.Fatal("baseline did not demonstrate injected peer enrollment")
			}
			if !strings.Contains(before, "preshared_key="+auditHex(psk)+"\n") {
				t.Fatal("fixture did not initially configure a PSK")
			}
			if strings.Contains(after, "preshared_key="+auditHex(psk)+"\n") {
				t.Fatal("baseline did not demonstrate PSK removal")
			}
			rogueBlock := strings.SplitN(strings.SplitN(after, "public_key="+auditHex(roguePub)+"\n", 2)[1], "\npublic_key=", 2)[0]
			// IpcGet iterates a map of peers, so the route can be the last
			// field in a split block with no trailing newline.
			if !strings.Contains("\n"+rogueBlock+"\n", "\nallowed_ip=10.89.0.2/32\n") {
				t.Fatalf("baseline did not demonstrate route reassignment to unconfigured peer: rogue=%s legitimate=%s after=%q", auditHex(roguePub), auditHex(legitimatePub), after)
			}
			legitimateBlock := strings.SplitN(strings.SplitN(after, "public_key="+auditHex(legitimatePub)+"\n", 2)[1], "\npublic_key=", 2)[0]
			if strings.Contains("\n"+legitimateBlock+"\n", "\nallowed_ip=10.89.0.2/32\n") {
				t.Fatal("configured peer retained route after attempted reassignment")
			}
			if len(cfg.Peers) != 1 || cfg.Peers[0].PublicKey == base64.StdEncoding.EncodeToString(roguePub[:]) {
				t.Fatal("fixture configuration already authorized the rogue peer")
			}
			packet := tuntest.Ping(netip.MustParseAddr("10.89.0.2"), netip.MustParseAddr("10.89.0.1"))
			select {
			case ct.Outbound <- packet:
			case <-time.After(5 * time.Second):
				t.Fatal("timed out writing synthetic packet into local TUN")
			}
			select {
			case received := <-rogueTun.Inbound:
				if !bytes.Equal(packet, received) {
					t.Fatal("rogue WG peer received a different plaintext packet")
				}
			case <-time.After(10 * time.Second):
				t.Fatal("rogue WG peer did not receive the tunneled packet")
			}
			t.Log("DEMONSTRATED: authenticated discovery record added an unconfigured WireGuard peer, reassigned the configured route to it, and removed the existing peer's PSK")
			t.Log("DEMONSTRATED: an end-to-end synthetic WireGuard handshake delivered the captured route's plaintext packet to the rogue peer")
			t.Log("No WireGuard handshake and no PSK knowledge were needed for the configuration change")
		})
	}
}
