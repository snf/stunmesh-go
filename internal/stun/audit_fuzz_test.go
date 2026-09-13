//go:build security_audit

package stun

import (
	"context"
	"net"
	"testing"

	stunmsg "github.com/pion/stun/v3"
)

// FuzzAuditDesktopBindingResponse exercises the Pion decoder and the
// proxy-backed desktop STUN response parser with bounded untrusted packets.
// It does not test source-address validation or authorize the mapped address.
func FuzzAuditDesktopBindingResponse(f *testing.F) {
	txn := [12]byte{0x21, 0x43, 0x65, 0x87, 0x09, 0xab, 0xcd, 0xef, 1, 2, 3, 4}
	valid, err := stunmsg.Build(
		stunmsg.NewTransactionIDSetter(txn),
		stunmsg.BindingSuccess,
		&stunmsg.XORMappedAddress{IP: net.IPv4(203, 0, 113, 9), Port: 41414},
	)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid.Raw)
	f.Add([]byte{})
	f.Add(make([]byte, 20))

	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 4*1024 {
			t.Skip()
		}
		_, _, _ = parseBindingResponse(context.Background(), raw, txn)
	})
}
