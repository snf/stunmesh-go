package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Original exploit demonstrations remain on the audit branch. These tests
// now require rejection without a panic, rather than reproducing acceptance.
func TestSecurityInvalidConfigurationRejected(t *testing.T) {
	for _, data := range []string{
		"ping_monitor:\n  interval: -1s\n  timeout: 0s\n",
		"refresh_interval: 0s\n",
		"refresh_interval: 999999999s\n",
		"plugins:\n  store:\n    &000: 0000000\n00000000: 00000000",
		"refresh_interval: 30s\nrefresh_interval: 60s\n",
		"plugins:\n  null: {}\n",
		"stun:\n  addresses: [192.0.2.1:65536]\n",
		"interfaces:\n  wg0:\n    peers:\n      peer:\n        public_key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n",
		strings.Repeat("x", 256*1024+1),
	} {
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path, ""); err == nil {
			t.Fatal("accepted unsafe fixture")
		}
	}
}
