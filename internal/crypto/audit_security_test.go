//go:build security_audit

package crypto

import (
	"context"
	"testing"

	"github.com/tjjh89017/stunmesh-go/internal/ctrl"
	"github.com/tjjh89017/stunmesh-go/internal/entity"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// The NaCl box shares a symmetric X25519 result in both directions, and the
// plaintext does not bind a record to its sender, recipient or DHT slot.
// Passing demonstrates that one peer can accept its own copied record as
// though it came from the other peer. This affects discovery availability;
// it does not forge a WireGuard transport packet.
func TestAuditEncryptedRecordAcceptsReverseDirection(t *testing.T) {
	a, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	b, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	data := `{"ipv4":"192.0.2.7:51820"}`
	bPub := b.PublicKey()
	pubB := entity.PeerPublicKey(bPub)
	sealed, err := NewEndpoint().Encrypt(context.Background(), &ctrl.EndpointEncryptRequest{
		PeerPublicKey: pubB, PrivateKey: entity.PrivateKey(a), Content: data,
	})
	if err != nil {
		t.Fatal(err)
	}
	// A reads the same ciphertext, expecting it to be a B-to-A record.
	opened, err := NewEndpoint().Decrypt(context.Background(), &ctrl.EndpointDecryptRequest{
		PeerPublicKey: pubB, PrivateKey: entity.PrivateKey(a), Data: sealed.Data,
	})
	if err != nil {
		t.Fatal(err)
	}
	if opened.Content != data {
		t.Fatalf("unexpected reflected plaintext %q", opened.Content)
	}
	t.Log("DEMONSTRATED: endpoint ciphertext has no sender/recipient/slot binding and can be reflected between peers")
}

// The NaCl box implementation uses curve25519.ScalarMult, which returns an
// all-zero shared point for low-order public keys. A malformed configured WG
// peer key can therefore make discovery encryption decryptable without either
// participant's private key. This does not make that invalid peer handshake.
func TestAuditLowOrderPeerKeyMakesDiscoveryRecordPublic(t *testing.T) {
	local, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	outsider, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	var lowOrder entity.PeerPublicKey // all-zero point
	plain := `{"ipv4":"192.0.2.7:51820"}`
	sealed, err := NewEndpoint().Encrypt(context.Background(), &ctrl.EndpointEncryptRequest{
		PeerPublicKey: lowOrder, PrivateKey: entity.PrivateKey(local), Content: plain,
	})
	if err != nil {
		t.Fatal(err)
	}
	opened, err := NewEndpoint().Decrypt(context.Background(), &ctrl.EndpointDecryptRequest{
		PeerPublicKey: lowOrder, PrivateKey: entity.PrivateKey(outsider), Data: sealed.Data,
	})
	if err != nil {
		t.Fatal(err)
	}
	if opened.Content != plain {
		t.Fatalf("expected outsider to open malformed-key record: content=%q", opened.Content)
	}
	t.Log("DEMONSTRATED: a low-order configured peer key makes endpoint-record encryption public, even though its WireGuard handshake cannot complete")
}
