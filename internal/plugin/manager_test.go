package plugin

import (
	"context"
	"errors"
	"testing"

	pluginapi "github.com/tjjh89017/stunmesh-go/pluginapi"
)

type fakeCloserStore struct{ closed int }

func (f *fakeCloserStore) Get(context.Context, string) ([]string, error) { return nil, nil }
func (f *fakeCloserStore) Set(context.Context, string, string) error     { return nil }
func (f *fakeCloserStore) Close() error                                  { f.closed++; return nil }

func TestManagerRejectsExecutableAndUnknownStoresAtomically(t *testing.T) {
	m := NewManager()
	old := &fakeCloserStore{}
	m.plugins["existing"] = old
	for _, def := range []pluginapi.PluginDefinition{
		{Type: "exec", Config: pluginapi.PluginConfig{"command": "/bin/sh"}},
		{Type: "shell", Config: pluginapi.PluginConfig{"command": "true"}},
		{Type: "builtin", Config: pluginapi.PluginConfig{"name": "cloudflare", "token": "SECRET"}},
		{Type: "builtin", Config: pluginapi.PluginConfig{"name": "opendht", "dedup": true}},
		{Type: "builtin", Config: pluginapi.PluginConfig{"name": "opendht", "command": "true"}},
	} {
		if err := m.LoadPlugins(context.Background(), map[string]pluginapi.PluginDefinition{"bad": def}); err == nil {
			t.Fatal("unsafe store admitted")
		}
		if got, _ := m.GetPlugin("existing"); got != old || old.closed != 0 {
			t.Fatal("failed configuration damaged existing store")
		}
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil || old.closed != 1 {
		t.Fatal("close not idempotent")
	}
}

func TestManagerOpenDHTOnly(t *testing.T) {
	m := NewManager()
	defer m.Close()
	defs := map[string]pluginapi.PluginDefinition{"dht": {Type: "builtin", Config: pluginapi.PluginConfig{"name": "opendht", "endpoint": "https://example.invalid"}}}
	if err := m.LoadPlugins(context.Background(), defs); err != nil {
		t.Fatal(err)
	}
	if store, err := m.GetPlugin("dht"); err != nil || store == nil {
		t.Fatal("missing OpenDHT store")
	}

	if _, err := m.GetPlugin("unknown"); err == nil {
		t.Fatal(errors.New("unknown store accepted"))
	}
}
