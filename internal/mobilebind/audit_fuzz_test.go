//go:build mobile && security_audit

package mobilebind

import (
	"encoding/binary"
	"testing"
)

// Internet-facing STUN messages share the WireGuard UDP socket. Mutate a
// syntactically valid binding response and truncated/corrupt variants to
// check that the demux/parser never panics on untrusted datagrams.
func FuzzAuditMobileSTUNResponse(f *testing.F) {
	valid := make([]byte, 32)
	binary.BigEndian.PutUint16(valid[0:2], stunBindingSuccess)
	binary.BigEndian.PutUint16(valid[2:4], 12)
	binary.BigEndian.PutUint32(valid[4:8], stunMagicCookie)
	copy(valid[8:20], []byte("AUDIT-TXN-01"))
	binary.BigEndian.PutUint16(valid[20:22], attrXorMappedAddress)
	binary.BigEndian.PutUint16(valid[22:24], 8)
	valid[25] = 1
	valid[26], valid[27] = 0x21, 0x12
	valid[28], valid[29], valid[30], valid[31] = 0x21, 0x12, 0xa4, 0x42
	f.Add(valid)
	f.Add(valid[:19])
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, packet []byte) {
		if len(packet) > 65535 {
			t.Skip()
		}
		if !IsSTUN(packet) {
			return
		}
		_, _ = parseBindingResponse(packet, TxnIDOf(packet))
	})
}
