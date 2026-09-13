//go:build security_audit

package wgproxy

import (
	"net/netip"
	"testing"

	"github.com/rs/zerolog"
)

// An endpoint collision can happen when two configured peers publish the same
// apparent UDP address. Updating either peer must not remove the other's live
// source mapping. This test records the current failing behavior.
func TestAuditEndpointCollisionInvalidatesOtherPeerOnReprogram(t *testing.T) {
	logger := zerolog.Nop()
	d := NewDemux(&logger)
	var first, second PeerKey
	first[0], second[0] = 1, 2
	shared := netip.MustParseAddrPort("192.0.2.1:51820")
	moved := netip.MustParseAddrPort("192.0.2.2:51820")
	packet := []byte{1, 0, 0, 0}

	d.Program(first, shared)
	d.Program(second, shared)
	if got := d.Classify(shared, packet); got.Bucket != BucketRelay || got.Peer != second {
		t.Fatalf("collision setup did not route to second peer: %+v", got)
	}
	d.Program(first, moved)
	if got := d.Classify(shared, packet); got.Bucket != BucketDrop {
		t.Fatalf("expected the current stale-map deletion to drop second peer, got %+v", got)
	}
	if got := d.Classify(moved, packet); got.Bucket != BucketRelay || got.Peer != first {
		t.Fatalf("first peer's moved endpoint was not programmed: %+v", got)
	}
}
