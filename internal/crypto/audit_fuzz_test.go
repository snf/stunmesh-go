//go:build security_audit

package crypto

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/tjjh89017/stunmesh-go/internal/ctrl"
	"github.com/tjjh89017/stunmesh-go/internal/entity"
	"golang.org/x/crypto/curve25519"
)

// FuzzAuditEndpointDecrypt probes the exact hex/nonce/MAC parsing boundary
// with arbitrary bytes as well as mutations of a valid synthetic record.
func FuzzAuditEndpointDecrypt(f *testing.F) {
	localPriv := [32]byte{1, 3, 3, 7}
	peerPriv := [32]byte{2, 4, 6, 8}
	localPub, err := curve25519.X25519(localPriv[:], curve25519.Basepoint)
	if err != nil {
		f.Fatal(err)
	}
	peerPub, err := curve25519.X25519(peerPriv[:], curve25519.Basepoint)
	if err != nil {
		f.Fatal(err)
	}
	var localPubKey, peerPubKey [32]byte
	copy(localPubKey[:], localPub)
	copy(peerPubKey[:], peerPub)
	valid, err := NewEndpoint().Encrypt(context.Background(), &ctrl.EndpointEncryptRequest{
		PeerPublicKey: entity.PeerPublicKey(localPubKey),
		PrivateKey: entity.PrivateKey(peerPriv),
		Content: `{"ipv4":"127.0.0.1:51820"}`,
	})
	if err != nil {
		f.Fatal(err)
	}
	decoded, err := hex.DecodeString(valid.Data)
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte{})
	f.Add([]byte{0, 1, 2, 3})
	f.Add(decoded)
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = NewEndpoint().Decrypt(context.Background(), &ctrl.EndpointDecryptRequest{
			PeerPublicKey: entity.PeerPublicKey(peerPubKey),
			PrivateKey: entity.PrivateKey(localPriv),
			Data: hex.EncodeToString(raw),
		})
	})
}
