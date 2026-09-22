//go:build security_audit

package wgproxy

import (
	"github.com/rs/zerolog"
	"net/netip"
	"testing"
)

func TestAuditEndpointCollisionCannotStealOrDeleteMapping(t *testing.T) {
	log := zerolog.Nop()
	d := NewDemux(&log)
	a, b := PeerKey{1}, PeerKey{2}
	shared := netip.MustParseAddrPort("192.0.2.1:51820")
	moved := netip.MustParseAddrPort("192.0.2.2:51820")
	packet := []byte{1, 0, 0, 0}
	if d.Program(a, shared) != nil {
		t.Fatal("first owner")
	}
	if d.Program(b, shared) == nil {
		t.Fatal("collision accepted")
	}
	d.Unprogram(b)
	if got := d.Classify(shared, packet); got.Bucket != BucketRelay || got.Peer != a {
		t.Fatal("failed owner removed valid mapping")
	}
	if d.Program(b, moved) != nil {
		t.Fatal("distinct endpoint refused")
	}
	if d.Program(a, moved) == nil {
		t.Fatal("second collision accepted")
	}
	if got := d.Classify(shared, packet); got.Peer != a {
		t.Fatal("collision mutated old mapping")
	}
}
