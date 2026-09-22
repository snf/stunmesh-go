//go:build mobile && security_audit && (linux || android)

package mobile

import (
	"strings"
	"testing"
)

// Regression cases from the historical audit. Vulnerable reproductions remain
// on the original audit branch; current gates require rejection.
func TestAuditExecutablePluginsAndLowOrderKeysRejected(t *testing.T) {
	base := minimalConfigJSON(validKeyB64(1), validKeyB64(2))
	base = strings.TrimSpace(base)
	for _, kind := range []string{"exec", "shell", "cloudflare"} {
		raw := base[:len(base)-1] + `,"plugins":[{"instance":"evil","type":"` + kind + `","name":"opendht","config":{"command":"/bin/sh"}}]}`
		if _, err := parseConfig(raw); err == nil {
			t.Fatal("executable plugin accepted")
		}
	}
	if _, err := parseConfig(minimalConfigJSON(validKeyB64(1), validKeyB64(0))); err == nil {
		t.Fatal("low-order peer accepted")
	}
}
