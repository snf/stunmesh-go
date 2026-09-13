//go:build security_audit

package config

import (
	"os"
	"path/filepath"
	"testing"
)

// A minimized local fuzz input reaches a nil map key inside mapstructure v2.5.0
// after YAML parsing. Keep the observation separate from production tests: the
// desired post-fix behavior is a returned validation error, not a panic.
func TestAuditYAMLAnchorMappingPanicsDuringConfigLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	data := "stun:\n  addresses: [192.0.2.1:3478]\nplugins:\n  store:\n    &000: 0000000\n00000000: 00000000"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if recovered := recover(); recovered == nil {
			t.Fatal("expected the observed nil-map-key panic")
	}
	}()
	_, _ = Load(path, "")
}
