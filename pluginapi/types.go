package pluginapi

import "errors"

// PluginConfig holds configuration for a plugin
type PluginConfig map[string]interface{}

// PluginDefinition defines a plugin configuration from YAML
type PluginDefinition struct {
	Type   string       `mapstructure:"type"`
	Config PluginConfig `mapstructure:",remain"`
}

// ValidateDefinition is shared by file/mobile imports and the constructor.
// This fork has one built-in store, not a process/plugin execution API.
func ValidateDefinition(def PluginDefinition) error {
	if def.Type != "builtin" || def.Config["name"] != "opendht" {
		return errors.New("only built-in OpenDHT is supported")
	}
	for name, value := range def.Config {
		switch name {
		case "name", "endpoint", "endpoints", "timeout":
		case "dedup":
			if value != false {
				return errors.New("OpenDHT publication dedup must be disabled")
			}
		default:
			return errors.New("unsupported OpenDHT configuration field")
		}
	}
	return nil
}
