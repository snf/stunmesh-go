package plugin

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"

	"github.com/tjjh89017/stunmesh-go/internal/plugin/builtin/opendht"
	pluginapi "github.com/tjjh89017/stunmesh-go/pluginapi"
)

type Manager struct {
	plugins map[string]pluginapi.Store
}

func NewManager() *Manager {
	return &Manager{
		plugins: make(map[string]pluginapi.Store),
	}
}

func (m *Manager) LoadPlugins(ctx context.Context, definitions map[string]pluginapi.PluginDefinition) error {
	if len(definitions) > 8 {
		return errors.New("too many OpenDHT stores")
	}
	next := NewManager()
	for name, def := range definitions {
		store, err := m.createPlugin(ctx, def)
		if err != nil {
			_ = next.Close()
			return fmt.Errorf("store initialization failed: %w", err)
		}
		next.plugins[name] = store
	}
	_ = m.Close()
	m.plugins = next.plugins
	return nil
}

func (m *Manager) GetPlugin(name string) (pluginapi.Store, error) {
	store, ok := m.plugins[name]
	if !ok {
		return nil, errors.New("store not configured")
	}
	return store, nil
}

// Close closes every plugin instance that implements io.Closer, in sorted
// name order, and joins any errors. It is idempotent: after closing, the
// plugin set is emptied, so a second call is a no-op returning nil.
func (m *Manager) Close() error {
	var errs []error
	for _, name := range slices.Sorted(maps.Keys(m.plugins)) {
		closer, ok := m.plugins[name].(io.Closer)
		if !ok {
			continue
		}
		if err := closer.Close(); err != nil {
			errs = append(errs, fmt.Errorf("plugin %s: %w", name, err))
		}
	}
	clear(m.plugins)
	return errors.Join(errs...)
}

func (m *Manager) createPlugin(ctx context.Context, def pluginapi.PluginDefinition) (pluginapi.Store, error) {
	if err := pluginapi.ValidateDefinition(def); err != nil {
		return nil, err
	}
	return opendht.NewOpenDHTPlugin(def.Config)
}
