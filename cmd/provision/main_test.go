package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tjjh89017/stunmesh-go/internal/provision"
)

func TestCredentialOutputIsPrivateExclusiveAndValidated(t *testing.T) {
	dir := t.TempDir()
	secret := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	input, output := filepath.Join(dir, "psk"), filepath.Join(dir, "enrollment.json")
	if err := os.WriteFile(input, []byte(secret+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"new", "--server-key", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)), "--address", "10.77.0.2/32", "--routes", "10.77.0.1/32", "--stun", "stun.example.com:3478", "--opendht", "https://proxy.example.com", "--psk-file", input, "--out", output}
	if err := run(args); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	p, err := provision.Decode(b)
	if err != nil || p.PresharedKey != secret {
		t.Fatal("credential not preserved in intended output")
	}
	info, err := os.Stat(output)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("enrollment output is not owner-private")
	}
	if err := run(args); err == nil {
		t.Fatal("existing enrollment overwritten")
	}
	after, _ := os.ReadFile(output)
	if !bytes.Equal(after, b) {
		t.Fatal("existing enrollment changed")
	}
	args[len(args)-1] = filepath.Join(dir, "invalid.json")
	if err := os.WriteFile(input, []byte("secret-canary-not-a-key"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := run(args); err == nil || strings.Contains(err.Error(), "secret-canary") {
		t.Fatal("bad credential accepted or echoed")
	}
	if _, err := os.Stat(args[len(args)-1]); !os.IsNotExist(err) {
		t.Fatal("invalid enrollment created a file")
	}
	if err := os.WriteFile(input, []byte(secret+"\r\n"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(input)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	oldStdin := os.Stdin
	os.Stdin = file
	defer func() { os.Stdin = oldStdin }()
	args[len(args)-3] = "-"
	if err := run(args); err != nil {
		t.Fatal("stdin credential input failed", err)
	}
}
