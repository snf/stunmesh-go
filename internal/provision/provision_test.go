package provision

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

// This same public proposal is consumed by the Android admission tests.
func TestSharedAndroidProposal(t *testing.T) {
	b, err := os.ReadFile("testdata/enrollment-public.json")
	if err != nil {
		t.Fatal(err)
	}
	p, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if p.Address != "10.77.0.2/32" || len(p.AllowedIPs) != 1 || p.AllowedIPs[0] != "10.77.0.1/32" {
		t.Fatal("shared enrollment routes changed")
	}
}

func fixture() Proposal {
	return Proposal{Schema: Schema, ID: "01234567-89ab-4cde-8fab-0123456789ab", Name: "Server", Address: "10.77.0.2/32", ServerPublicKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)), AllowedIPs: []string{"10.77.0.1/32"}, STUN: []string{"stun.example.com:3478"}, OpenDHT: []string{"https://proxy.example.com"}, Protocol: "ipv4"}
}
func TestPublicRoundTripAndReply(t *testing.T) {
	p := fixture()
	b, e := p.Encode()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Decode(b); e != nil {
		t.Fatal(e)
	}
	r := Reply{Schema: "stunmesh-peer-v1", ID: p.ID, PublicKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32)), Addresses: []string{p.Address}}
	rb, _ := json.Marshal(r)
	if _, e = CheckReply(p, rb); e != nil {
		t.Fatal(e)
	}
	r.ID = NewID()
	rb, _ = json.Marshal(r)
	if _, e = CheckReply(p, rb); e == nil {
		t.Fatal("mismatched reply accepted")
	}
}
func TestPublicProposalCannotSmuggleSecretOrRoute(t *testing.T) {
	p := fixture()
	b, _ := p.Encode()
	for _, field := range []string{"private_key", "command", "encrypted_key", "psk_required"} {
		attack := string(b[:len(b)-1]) + `,"` + field + `":"canary"}`
		if _, e := Decode([]byte(attack)); e == nil {
			t.Fatal("secret/unknown field accepted")
		}
	}
	p.AllowedIPs = []string{"0.0.0.0/0"}
	if _, e := p.Encode(); e == nil {
		t.Fatal("default route accepted")
	}
	p = fixture()
	p.OpenDHT = []string{"https://user:canary@example.com"}
	if _, e := p.Encode(); e == nil {
		t.Fatal("credential URL accepted")
	}
}

func TestCredentialProposalAndPublicReply(t *testing.T) {
	b, err := os.ReadFile("testdata/enrollment-with-psk.json")
	if err != nil {
		t.Fatal(err)
	}
	p, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	psk := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	if p.PresharedKey != psk {
		t.Fatal("shared PSK fixture not preserved")
	}
	encoded, err := p.Encode()
	if err != nil || !bytes.Contains(encoded, []byte(psk)) {
		t.Fatal("credential missing from intended enrollment")
	}
	if bytes.Contains([]byte(fmt.Sprintf("%v %+v %#v", p, p, p)), []byte(psk)) {
		t.Fatal("ordinary formatting disclosed PSK")
	}
	r := Reply{Schema: "stunmesh-peer-v1", ID: p.ID, PublicKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32)), Addresses: []string{p.Address}}
	rb, _ := json.Marshal(r)
	if _, err := CheckReply(p, rb); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(rb, []byte(psk)) {
		t.Fatal("public reply disclosed PSK")
	}
	for _, value := range []any{"", "bad-secret-canary", base64.StdEncoding.EncodeToString(make([]byte, 32)), psk + "\n", nil, true, []string{psk}} {
		var doc map[string]any
		_ = json.Unmarshal(encoded, &doc)
		doc["preshared_key"] = value
		attack, _ := json.Marshal(doc)
		if _, err := Decode(attack); err == nil {
			t.Fatal("invalid shared credential accepted")
		}
	}
}
func FuzzPublicEnrollment(f *testing.F) {
	b, _ := fixture().Encode()
	f.Add(b)
	f.Add([]byte(`{"private_key":"canary"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		p, e := Decode(b)
		if e != nil {
			return
		}
		encoded, e := p.Encode()
		if e != nil {
			t.Fatal(e)
		}
		if _, e = Decode(encoded); e != nil {
			t.Fatal(e)
		}
	})
}
