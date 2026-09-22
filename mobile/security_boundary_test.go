//go:build mobile && (linux || android)

package mobile

import (
	"strings"
	"testing"

	"github.com/tjjh89017/stunmesh-go/internal/mobilebind"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

func TestSecurityInjectionCannotMutateAuthorization(t *testing.T) {
	cfg := &tunnelConfig{Interface: ifaceConfig{PrivateKey: validKeyB64(1)}, Peers: []peerConfig{{
		PublicKey: validKeyB64(2), PresharedKey: validKeyB64(3), AllowedIPs: []string{"10.89.0.2/32"},
	}}}
	dev := device.NewDevice(tuntest.NewChannelTUN().TUN(), mobilebind.New(nil), device.NewLogger(device.LogLevelSilent, ""))
	defer dev.Close()
	initial, err := buildUAPI(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := dev.IpcSet(initial); err != nil {
		t.Fatal(err)
	}
	before, err := dev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	rogue, _ := keyToHex(validKeyB64(4))
	payloads := []string{
		"192.0.2.1:9\npublic_key=" + rogue + "\nallowed_ip=10.89.0.2/32",
		"192.0.2.1:9\npreshared_key=" + strings.Repeat("0", 64),
		"192.0.2.1:9\nremove=true\ninvalid_option=1",
		"192.0.2.1:65537",
	}
	for _, value := range payloads {
		if update, err := buildPeerEndpointUAPI(cfg.Peers[0].PublicKey, value); err == nil || update != "" {
			t.Fatal("hostile endpoint reached WireGuard command generation")
		}
		cfg.Peers[0].Endpoint = value
		if text, err := buildUAPI(cfg); err == nil || text != "" {
			t.Fatal("hostile initial endpoint accepted")
		}
	}
	cfg.Peers[0].Endpoint = ""
	for _, route := range []string{"10.89.0.2/32\npublic_key=" + rogue, "0.0.0.0/0", "::/0", "128.0.0.0/1"} {
		cfg.Peers[0].AllowedIPs = []string{route}
		if text, err := buildUAPI(cfg); err == nil || text != "" {
			t.Fatal("hostile/broad route accepted")
		}
	}
	after, err := dev.IpcGet()
	if err != nil || before != after {
		t.Fatal("rejected input changed live peer keys, PSKs or routes")
	}
	// A subsequent valid endpoint update remains update-only, preserving the
	// authorized peer and PSK; rejection did not rely on a later repair.
	update, err := buildPeerEndpointUAPI(cfg.Peers[0].PublicKey, "192.0.2.1:9")
	if err != nil {
		t.Fatal(err)
	}
	if err := dev.IpcSet(update); err != nil {
		t.Fatal(err)
	}
	after, _ = dev.IpcGet()
	psk, _ := keyToHex(validKeyB64(3))
	if strings.Count(after, "public_key=") != 1 || strings.Contains(after, rogue) || !strings.Contains(after, "preshared_key="+psk) || !strings.Contains(after, "allowed_ip=10.89.0.2/32") {
		t.Fatal("valid endpoint update changed peer authorization")
	}
}

func TestSecurityConfigRejectsDuplicatesNullsAndWorkerLimits(t *testing.T) {
	base := minimalConfigJSON(validKeyB64(1), validKeyB64(2))
	for _, suffix := range []string{`,"refresh_interval_seconds":0`, `,"refresh_interval_seconds":-1`, `,"refresh_interval_seconds":241`, `,"name":"one","name":"two"`, `,"peers":null`} {
		raw := strings.TrimSpace(base)
		raw = raw[:len(raw)-1] + suffix + "}"
		if _, err := parseConfig(raw); err == nil {
			t.Fatal("invalid configuration accepted")
		}
	}
	if _, err := parseConfig(minimalConfigJSON(validKeyB64(1), validKeyB64(0))); err == nil {
		t.Fatal("low-order key accepted")
	}
}
