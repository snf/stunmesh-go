// Package stunwire is the shared, bounded STUN binding parser. STUN is address
// discovery only and provides no authorization of WireGuard peers.
package stunwire

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

type TxnID = [12]byte

const (
	stunHeaderSize       = 20
	stunMagicCookie      = 0x2112A442
	stunBindingRequest   = 0x0001
	stunBindingSuccess   = 0x0101
	attrMappedAddress    = 0x0001
	attrXorMappedAddress = 0x0020
)

func IsSTUN(b []byte) bool {
	return len(b) >= 20 && len(b) <= 2048 && b[0]&0xc0 == 0 && binary.BigEndian.Uint32(b[4:8]) == stunMagicCookie && int(binary.BigEndian.Uint16(b[2:4]))%4 == 0 && 20+int(binary.BigEndian.Uint16(b[2:4])) == len(b)
}
func TxnIDOf(b []byte) (id TxnID) {
	if len(b) >= 20 {
		copy(id[:], b[8:20])
	}
	return
}
func BuildRequest() ([]byte, TxnID, error) {
	var txn TxnID
	if _, err := rand.Read(txn[:]); err != nil {
		return nil, txn, fmt.Errorf("stun: txn id: %w", err)
	}
	msg := make([]byte, stunHeaderSize)
	binary.BigEndian.PutUint16(msg[0:2], stunBindingRequest)
	binary.BigEndian.PutUint16(msg[2:4], 0)
	binary.BigEndian.PutUint32(msg[4:8], stunMagicCookie)
	copy(msg[8:20], txn[:])
	return msg, txn, nil
}

func ParseResponse(msg []byte, txn TxnID) (netip.AddrPort, error) {
	if !IsSTUN(msg) || TxnIDOf(msg) != txn || binary.BigEndian.Uint16(msg[:2]) != stunBindingSuccess {
		return netip.AddrPort{}, errors.New("invalid STUN binding response")
	}
	attrs := msg[stunHeaderSize:]
	var mapped, xor netip.AddrPort
	for len(attrs) > 0 {
		if len(attrs) < 4 {
			return netip.AddrPort{}, errors.New("truncated STUN attribute")
		}
		kind := binary.BigEndian.Uint16(attrs[:2])
		length := int(binary.BigEndian.Uint16(attrs[2:4]))
		padded := (length + 3) &^ 3
		if padded+4 > len(attrs) {
			return netip.AddrPort{}, errors.New("truncated STUN attribute padding")
		}
		if kind == attrXorMappedAddress || kind == attrMappedAddress {
			value, err := decodeAddress(attrs[4:4+length], txn, kind == attrXorMappedAddress)
			if err != nil {
				return netip.AddrPort{}, err
			}
			if kind == attrXorMappedAddress {
				if xor.IsValid() {
					return netip.AddrPort{}, errors.New("duplicate mapped address")
				}
				xor = value
			} else {
				if mapped.IsValid() {
					return netip.AddrPort{}, errors.New("duplicate mapped address")
				}
				mapped = value
			}
		}
		attrs = attrs[4+padded:]
	}
	if xor.IsValid() {
		return xor, nil
	}
	if mapped.IsValid() {
		return mapped, nil
	}
	return netip.AddrPort{}, errors.New("missing STUN mapped address")
}

func decodeAddress(value []byte, txn TxnID, xored bool) (netip.AddrPort, error) {
	if len(value) < 8 || value[0] != 0 {
		return netip.AddrPort{}, errors.New("stun: short address attribute")
	}
	family := value[1]
	port := binary.BigEndian.Uint16(value[2:4])
	if xored {
		port ^= uint16(stunMagicCookie >> 16)
	}

	var rawAddr []byte
	switch family {
	case 0x01: // IPv4
		if len(value) != 8 {
			return netip.AddrPort{}, errors.New("stun: short IPv4 attribute")
		}
		rawAddr = append([]byte(nil), value[4:8]...)
		if xored {
			var cookie [4]byte
			binary.BigEndian.PutUint32(cookie[:], stunMagicCookie)
			for i := range rawAddr {
				rawAddr[i] ^= cookie[i]
			}
		}
	case 0x02: // IPv6: xor with magic cookie followed by the txn id
		if len(value) != 20 {
			return netip.AddrPort{}, errors.New("stun: short IPv6 attribute")
		}
		rawAddr = append([]byte(nil), value[4:20]...)
		if xored {
			var mask [16]byte
			binary.BigEndian.PutUint32(mask[0:4], stunMagicCookie)
			copy(mask[4:], txn[:])
			for i := range rawAddr {
				rawAddr[i] ^= mask[i]
			}
		}
	default:
		return netip.AddrPort{}, fmt.Errorf("stun: unknown address family %#02x", family)
	}

	addr, ok := netip.AddrFromSlice(rawAddr)
	if !ok {
		return netip.AddrPort{}, errors.New("stun: invalid address")
	}
	if port == 0 || !addr.IsGlobalUnicast() || addr.Is4In6() {
		return netip.AddrPort{}, errors.New("stun: invalid mapped endpoint")
	}
	return netip.AddrPortFrom(addr, port), nil
}
