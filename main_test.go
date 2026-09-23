package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tjjh89017/stunmesh-go/internal/linuxprofile"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// A caller capturing stdout does not prevent Podman from retaining that output.
// Exercise the real CLI boundary: confidential results must only reach files.
func TestConfidentialCandidatesNeverReachStdout(t *testing.T) {
	server, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	client, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	psk, err := wgtypes.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	p := linuxprofile.Profile{
		Schema: linuxprofile.Schema, Name: "fixture", PrivateKey: client.String(),
		PresharedKey: psk.String(), ServerPublicKey: server.PublicKey().String(),
		Address: "10.77.0.253/32", AllowedIPs: []string{"10.77.0.1/32"},
		Endpoint: "192.0.2.1:51824", STUN: []string{"stun.example.com:3478"},
		OpenDHT:   []string{"https://dht.example.com"},
		Hostnames: map[string]string{"nas": "10.77.0.1"}, LANHostnames: map[string]string{"nas-lan": "192.168.0.10"},
	}
	dir, output := t.TempDir(), t.TempDir()
	if err := os.Chmod(output, 0700); err != nil {
		t.Fatal(err)
	}
	yml, err := p.Discovery()
	if err != nil {
		t.Fatal(err)
	}
	for name, text := range map[string]string{
		"wg0.conf":     "[Interface]\nPrivateKey = " + server.String() + "\nListenPort = 51824\n",
		"stunmesh.yml": strings.Replace(string(yml), linuxprofile.Interface+":", "wg0:", 1),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	input, err := os.CreateTemp(t.TempDir(), "stdin-")
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	if err := json.NewEncoder(input).Encode(p); err != nil {
		t.Fatal(err)
	}
	if _, err := input.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	logged, err := os.CreateTemp(t.TempDir(), "stdout-")
	if err != nil {
		t.Fatal(err)
	}
	defer logged.Close()
	oldIn, oldOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = input, logged
	defer func() { os.Stdin, os.Stdout = oldIn, oldOut }()
	if err := linuxCommand([]string{"linux-activate", dir, output}); err != nil {
		t.Fatal(err)
	}
	if st, err := logged.Stat(); err != nil || st.Size() != 0 {
		t.Fatal("confidential command emitted output")
	}
	for _, name := range []string{"wg0.conf", "stunmesh.yml"} {
		st, err := os.Stat(filepath.Join(output, name))
		if err != nil || st.Mode().Perm() != 0600 {
			t.Fatal("missing private candidate")
		}
	}
	if _, err := input.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	if err := linuxCommand([]string{"linux-activate", dir, output}); err == nil {
		t.Fatal("overwrote candidate")
	}
	for _, args := range [][]string{nil, {"linux-issue"}, {"linux-activate", dir}, {"linux-revoke", dir}} {
		if err := linuxCommand(args); err == nil {
			t.Fatal("accepted operation without explicit output path")
		}
	}
}
