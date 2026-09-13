//go:build security_audit

package config

import (
	"os"
	"path/filepath"
	"testing"

	"go.yaml.in/yaml/v3"
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

// A first campaign found a nil YAML mapping key that crashes mapstructure.
// This follow-up excludes that known input class before calling the unchanged
// production loader, so fuzzing can search for independent failures. The
// prefilter is audit-only and is not a proposed fix.
func FuzzAuditConfigLoaderAfterNilKeyFilter(f *testing.F) {
	f.Add([]byte("refresh_interval: 60s\n"))
	f.Add([]byte("plugins:\n  store:\n    config:\n      endpoints: [https://example.invalid]\n"))
	f.Add([]byte("interfaces:\n  wg0:\n    peers: [one, two]\n"))
	f.Add([]byte("plugins:\n  store:\n    &000: 0000000\n00000000: 00000000\n"))
	f.Fuzz(func(t *testing.T, suffix []byte) {
		if len(suffix) > 1<<16 {
			t.Skip()
		}
		data := append([]byte("stun:\n  addresses: [192.0.2.1:3478]\n"), suffix...)
		var raw map[string]any
		if err := yaml.Unmarshal(data, &raw); err != nil || auditHasNilMappingKey(raw, 0) {
			return
		}
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		_, _ = Load(path, "")
	})
}

func auditHasNilMappingKey(v any, depth int) bool {
	if depth > 128 {
		return true
	}
	switch x := v.(type) {
	case map[any]any:
		for key, child := range x {
			if key == nil || auditHasNilMappingKey(child, depth+1) {
				return true
			}
		}
	case map[string]any:
		for _, child := range x {
			if auditHasNilMappingKey(child, depth+1) {
				return true
			}
		}
	case []any:
		for _, child := range x {
			if auditHasNilMappingKey(child, depth+1) {
				return true
			}
		}
	}
	return false
}
