package discovery

import (
	"net/netip"
	"strings"
	"testing"
)

func TestHintSchemaAndScope(t *testing.T) {
	for _, input := range []string{`{"version":1,"ipv4":"198.51.100.1:3"}`, `{"version":2,"ipv4":"198.51.100.1:3","private_key":"x"}`, `{"version":2,"ipv4":"198.51.100.1:3","ipv4":"198.51.100.2:3"}`, `{"version":2,"ipv4":"127.0.0.1:4"}`, strings.Repeat("x", MaxRecordBytes+1)} {
		if _, err := Decode(input); err == nil {
			t.Fatal("unsafe hint accepted")
		}
	}
	if Allowed("192.168.0.1:8", nil) || Allowed("100.64.1.1:8", nil) || Allowed("[fe80::1]:8", nil) {
		t.Fatal("non-public scope accepted")
	}
	if !Allowed("192.168.0.1:8", []netip.Prefix{netip.MustParsePrefix("192.168.0.0/24")}) || !Allowed("198.51.100.1:8", nil) {
		t.Fatal("permitted scope refused")
	}
}
func FuzzRecord(f *testing.F) {
	f.Add(`{"version":2,"ipv4":"198.51.100.1:4"}`)
	f.Fuzz(func(t *testing.T, s string) {
		r, e := Decode(s)
		if e == nil {
			out, e := Encode(r)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = Decode(out); e != nil {
				t.Fatal(e)
			}
		}
	})
}
