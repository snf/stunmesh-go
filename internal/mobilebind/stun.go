//go:build mobile

package mobilebind

import (
	"context"
	"errors"
	"fmt"
	"github.com/tjjh89017/stunmesh-go/internal/stunwire"
	"net/netip"
	"time"
)

// STUN message types and attributes (RFC 8489).
const (
	stunBindingRequest   = 0x0001
	stunBindingSuccess   = 0x0101
	attrMappedAddress    = 0x0001
	attrXorMappedAddress = 0x0020
)

// Retransmit schedule: RTO 500ms doubling per RFC 8489 section 6.2.1,
// bounded by the context deadline.
const (
	stunInitialRTO = 500 * time.Millisecond
	stunMaxRetries = 4
)

var ErrStunTimeout = errors.New("stun: no response")

// Discover sends a STUN binding request to dst from the shared WG socket and
// returns the reflexive address. dst's address family selects which socket
// the request leaves by (see connFor), so it is also what picks the family
// being discovered. The response arrives through the demux path, so the
// mapping it reports is the one WG traffic uses.
//
// dst is an already-resolved address on purpose. Resolving a STUN hostname
// here would mean the platform resolver, which on android routes over the
// default network -- the tunnel itself, once up -- and so cannot be relied on
// to answer while discovery is still trying to establish that tunnel. The
// caller resolves through the escaped path instead; see mobile's
// controller.resolveSTUN.
func (b *Bind) Discover(ctx context.Context, dst netip.AddrPort) (netip.AddrPort, error) {
	if !dst.IsValid() {
		return netip.AddrPort{}, errors.New("stun: invalid destination")
	}

	req, txn, err := buildBindingRequest()
	if err != nil {
		return netip.AddrPort{}, err
	}
	ch := b.registry.Register(txn, dst)
	defer b.registry.Unregister(txn)

	rto := stunInitialRTO
	for attempt := 0; attempt < stunMaxRetries; attempt++ {
		if err := b.SendTo(dst, req); err != nil {
			return netip.AddrPort{}, fmt.Errorf("stun: send: %w", err)
		}
		timer := time.NewTimer(rto)
		waiting := true
		for waiting {
			select {
			case resp := <-ch:
				result, err := parseBindingResponse(resp, txn)
				if err == nil {
					timer.Stop()
					return result, nil
				} // ignore malformed replies until the original deadline
			case <-ctx.Done():
				timer.Stop()
				return netip.AddrPort{}, ctx.Err()
			case <-timer.C:
				rto *= 2
				waiting = false
			}
		}

	}
	return netip.AddrPort{}, ErrStunTimeout
}

func buildBindingRequest() ([]byte, TxnID, error) { return stunwire.BuildRequest() }
func parseBindingResponse(msg []byte, txn TxnID) (netip.AddrPort, error) {
	return stunwire.ParseResponse(msg, txn)
}
