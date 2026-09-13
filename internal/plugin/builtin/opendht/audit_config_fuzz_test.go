//go:build (builtin_opendht || builtin_all) && security_audit

package opendht

import (
	"encoding/json"
	"testing"

	pluginapi "github.com/tjjh89017/stunmesh-go/pluginapi"
)

// FuzzAuditOpenDHTConfigConstructor checks the local config-to-HTTP-client
// boundary for panics. Construction makes no network request. This does not
// test the separate public DHT response parser or authorize any config value.
func FuzzAuditOpenDHTConfigConstructor(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"timeout":"15s","endpoints":["https://example.invalid"]}`))
	f.Add([]byte(`{"timeout":"-1s","endpoints":["https://example.invalid",12]}`))
	f.Add([]byte(`{"endpoint":"https://user:pass@example.invalid/path?x=1","magic":"x"}`))
	f.Add([]byte(`{"endpoint":"http://127.0.0.1:9","timeout":0}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 32*1024 {
			t.Skip()
		}
		var values map[string]any
		if err := json.Unmarshal(raw, &values); err != nil || values == nil {
			return
		}
		if _, ok := values["endpoint"]; !ok {
			values["endpoint"] = "https://example.invalid"
		}
		store, err := NewOpenDHTPlugin(pluginapi.PluginConfig(values))
		if err == nil {
			_ = store.(*OpenDHTPlugin).Close()
		}
	})
}
