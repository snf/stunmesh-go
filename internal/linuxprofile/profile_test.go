package linuxprofile

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func fixture() Profile {
	k := wgtypes.Key{8, 2, 3}
	k[31] = 64
	s := wgtypes.Key{16, 5, 6}
	s[31] = 64
	return Profile{Schema: Schema, Name: "laptop", PrivateKey: k.String(), PresharedKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)),
		ServerPublicKey: s.PublicKey().String(), Address: "10.77.0.253/32", AllowedIPs: []string{"10.77.0.1/32", "10.77.0.21/32", "10.77.0.23/32"},
		Endpoint: "192.168.0.10:51824", STUN: []string{"stun.example.com:3478"}, OpenDHT: []string{"https://dht.example.com"},
		Hostnames: map[string]string{"nas": "10.77.0.1"}, LANHostnames: map[string]string{"nas-lan": "192.168.0.10"}}
}
func TestBoundary(t *testing.T) {
	good, _ := json.Marshal(fixture())
	if _, err := Decode(good); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Profile){
		"default route":             func(p *Profile) { p.AllowedIPs = []string{"0.0.0.0/0"} },
		"other destination":         func(p *Profile) { p.AllowedIPs = append(p.AllowedIPs, "192.168.0.0/24") },
		"peer collision":            func(p *Profile) { p.Address = "10.77.0.1/32" },
		"hook":                      func(p *Profile) { p.Endpoint = "192.168.0.10:51824\nPostUp=bad" },
		"hostname injection":        func(p *Profile) { p.Hostnames = map[string]string{"nas\nlocalhost": "10.77.0.1"} },
		"wrong hostname route":      func(p *Profile) { p.Hostnames = map[string]string{"nas": "192.168.0.10"} },
		"shadow localhost":          func(p *Profile) { p.Hostnames = map[string]string{"localhost": "10.77.0.1"} },
		"LAN without escape suffix": func(p *Profile) { p.LANHostnames = map[string]string{"nas": "192.168.0.10"} },
		"zero key":                  func(p *Profile) { p.PrivateKey = base64.StdEncoding.EncodeToString(make([]byte, 32)) },
		"duplicate route":           func(p *Profile) { p.AllowedIPs = append(p.AllowedIPs, p.AllowedIPs[0]) },
	} {
		t.Run(name, func(t *testing.T) {
			p := fixture()
			mutate(&p)
			b, _ := json.Marshal(p)
			if _, err := Decode(b); err == nil {
				t.Fatal("accepted unsafe profile")
			}
		})
	}
	for _, raw := range []string{strings.Replace(string(good), `"schema":`, `"Schema":`, 1), strings.Replace(string(good), `"name":"laptop"`, `"name":"laptop","Name":"other"`, 1), strings.TrimSuffix(string(good), "}") + `,"command":"bad"}`, string(good) + "{}", `null`, strings.Repeat(" ", MaxBytes+1)} {
		if _, err := Decode([]byte(raw)); err == nil {
			t.Fatal("accepted invalid JSON boundary")
		}
	}
}
func TestNoSecretSummaryAndExclusiveOutput(t *testing.T) {
	p := fixture()
	b, _ := json.Marshal(p.Public())
	for _, s := range []string{p.PrivateKey, p.PresharedKey} {
		if bytes.Contains(b, []byte(s)) || strings.Contains(fmt.Sprintf("%v %#v", p, p), s) {
			t.Fatal("secret in summary")
		}
	}
	path := filepath.Join(t.TempDir(), "profile.json")
	if err := WriteNew(path, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := WriteNew(path, []byte("second")); err == nil {
		t.Fatal("overwrote profile")
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0600 {
		t.Fatal("permissions")
	}
}
func TestHostLifecycleInIsolatedNetwork(t *testing.T) {
	if os.Getenv("STUNMESH_ISOLATED_TEST_NETWORK") != "1" {
		t.Skip("requires scripts/sandbox.py --net-admin")
	}
	wg := "/artifacts/wg"
	ip := []string{"/artifacts/image-tools/ld-musl-x86_64.so.1", "/artifacts/image-tools/busybox", "ip"}
	r := Runtime{ip, wg}
	p := fixture()
	// Prove a foreign interface survives startup and cleanup attempts.
	if err := r.ip("link", "add", Interface, "type", "wireguard"); err != nil {
		t.Fatal(err)
	}
	if err := r.Setup(p, t.TempDir()); err == nil {
		t.Fatal("adopted foreign interface")
	}
	if err := r.Cleanup(p); err == nil {
		t.Fatal("removed foreign interface")
	}
	if err := r.ip("link", "delete", Interface); err != nil {
		t.Fatal(err)
	}
	if err := r.ip("route", "add", "unreachable", "10.77.0.1/32", "metric", "42777", "proto", "186"); err != nil {
		t.Fatal(err)
	}
	defer r.ip("route", "del", "unreachable", "10.77.0.1/32", "metric", "42777", "proto", "186")
	if err := r.Setup(p, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	defer r.Cleanup(p)
	b, err := exec.Command(ip[0], append(ip[1:], "route", "get", "10.77.0.1")...).Output()
	if err != nil || !bytes.Contains(b, []byte("dev "+Interface)) {
		t.Fatal("active route did not override guard")
	}
	ownedPath := filepath.Join(t.TempDir(), "interface.json")
	if err := r.CleanupOwned(p, ownedPath); err != nil {
		t.Fatal(err)
	}
	iface, err := net.InterfaceByName(Interface)
	if err != nil {
		t.Fatal("missing receipt must not remove an existing matching identity")
	}
	wrong, _ := json.Marshal(receipt{iface.Index + 1, p.PublicKey()})
	if err := WriteNew(ownedPath, wrong); err != nil {
		t.Fatal(err)
	}
	if err := r.CleanupOwned(p, ownedPath); err == nil {
		t.Fatal("foreign interface index accepted")
	}
	correct, _ := json.Marshal(receipt{iface.Index, p.PublicKey()})
	if err := os.WriteFile(ownedPath, correct, 0600); err != nil {
		t.Fatal(err)
	}
	if err := r.CleanupOwned(p, ownedPath); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command(ip[0], append(ip[1:], "route", "get", "10.77.0.1")...).Run(); err == nil {
		t.Fatal("stopped tunnel leaked to default route")
	}
	if err := r.Cleanup(p); err != nil {
		t.Fatal("cleanup not idempotent")
	}
}
