package linuxprofile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestServerEnrollmentTransaction(t *testing.T) {
	p := fixture()
	key := wgtypes.Key{16, 5, 6}
	key[31] = 64
	dir := t.TempDir()
	original := "[Interface]\nPrivateKey = " + key.String() + "\nListenPort = 51824\n"
	yml, _ := p.Discovery()
	yml = []byte(strings.Replace(string(yml), Interface+":", "wg0:", 1))
	if err := WriteNew(filepath.Join(dir, "wg0.conf"), []byte(original)); err != nil {
		t.Fatal(err)
	}
	if err := WriteNew(filepath.Join(dir, "stunmesh.yml"), yml); err != nil {
		t.Fatal(err)
	}
	s, err := LoadServer(dir)
	if err != nil {
		t.Fatal(err)
	}
	public, _ := json.Marshal(s.Public())
	if strings.Contains(string(public), key.String()) {
		t.Fatal("server private key disclosed")
	}
	b, err := s.Edited(p, false)
	if err != nil {
		t.Fatal(err)
	}
	var candidate map[string]string
	if json.Unmarshal(b, &candidate) != nil {
		t.Fatal("bad output")
	}
	if !strings.Contains(candidate["wg0.conf"], "AllowedIPs = 10.77.0.253/32\n") || strings.Contains(candidate["wg0.conf"], "AllowedIPs = 10.77.0.1/32") {
		t.Fatal("wrong server peer route direction")
	}
	for name, text := range candidate {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	s, err = LoadServer(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err = s.Edited(p, false)
	if err != nil {
		t.Fatal("repeat enrollment failed", err)
	}
	if strings.Count(string(b), "BEGIN LINUX") != 1 {
		t.Fatal("duplicate enrollment")
	}
	s, err = LoadServer(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err = s.Edited(p, true)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), p.PresharedKey) || strings.Contains(string(b), p.PublicKey()) {
		t.Fatal("revocation retained peer")
	}
	s, err = LoadServer(dir)
	if err != nil {
		t.Fatal(err)
	}
	other := p
	k := wgtypes.Key{24, 9, 10}
	k[31] = 64
	other.PrivateKey = k.String()
	if _, err = s.Edited(other, false); err == nil {
		t.Fatal("replaced another managed identity")
	}
	s.WG = original + "\n[Peer]\nPublicKey = " + p.PublicKey() + "\nAllowedIPs = 10.77.0.0/24\n"
	delete(s.Peers, "linux-laptop")
	if _, err = s.Edited(p, false); err == nil {
		t.Fatal("overlapping existing peer accepted")
	}
}
