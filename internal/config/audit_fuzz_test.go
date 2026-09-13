//go:build security_audit

package config

import (
	"os"
	"path/filepath"
	"testing"
)

// Exercise YAML decoding, mapstructure conversion, and validation together
// without network access or production configuration. A valid STUN seed
// avoids the missing-server warning in the fuzz loop.
func FuzzAuditConfigLoader(f *testing.F) {
	f.Add([]byte("refresh_interval: 60s\n"))
	f.Add([]byte("interfaces:\n  wg0:\n    protocol: ipv4\n    peers: []\n"))
	f.Add([]byte("plugins:\n  store:\n    type: builtin\n    name: opendht\n"))
	f.Add([]byte("refresh_interval: [bad, shape]\n"))
	f.Fuzz(func(t *testing.T, suffix []byte) {
		if len(suffix) > 1<<16 {
			t.Skip()
		}
		path := filepath.Join(t.TempDir(), "config.yaml")
		data := append([]byte("stun:\n  addresses: [192.0.2.1:3478]\n"), suffix...)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		_, _ = Load(path, "")
	})
}
