//go:build mobile && security_audit && (linux || android)

package mobile

import "testing"

// FuzzAuditMobileConfigDecode exercises the imported JSON-to-UAPI boundary.
// It looks for panics and resource misuse; it does not assert that accepted
// fields are safe. The separate adversarial tests demonstrate the known UAPI
// injection, so a passing fuzz run cannot be interpreted as authorization.
func FuzzAuditMobileConfigDecode(f *testing.F) {
	const key = "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	f.Add([]byte(`{"interface":{"private_key":"` + key + `"},"peers":[]}`))
	f.Add([]byte(`{"interface":{"private_key":"` + key + `"},"peers":[{"public_key":"` + key + `","allowed_ips":["10.0.0.0/24"]}]}`))
	f.Add([]byte(`{"interface":{"private_key":"` + key + `"},"plugins":[{"type":"builtin","name":"opendht","config":{"endpoints":["https://example.invalid"]}}]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 64*1024 {
			t.Skip()
		}
		cfg, err := parseConfig(string(raw))
		if err != nil {
			return
		}
		_, _ = buildUAPI(cfg)
	})
}
