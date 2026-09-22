//go:build mobile

package mobile

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/tjjh89017/stunmesh-go/internal/validation"
	pluginapi "github.com/tjjh89017/stunmesh-go/pluginapi"
)

// Config mirrors the JSON produced by the Android app (TunnelConfig.toJson).
// Field names follow the stunmesh-go YAML config where a counterpart exists.
type tunnelConfig struct {
	ID                     string       `json:"id"`
	Name                   string       `json:"name"`
	Interface              ifaceConfig  `json:"interface"`
	Peers                  []peerConfig `json:"peers"`
	Plugins                []pluginDef  `json:"plugins"`
	Stun                   stunConfig   `json:"stun"`
	RefreshIntervalSeconds int          `json:"refresh_interval_seconds"`
	Log                    logConfig    `json:"log"`
}

type ifaceConfig struct {
	PrivateKey string   `json:"private_key"`
	Addresses  []string `json:"addresses"`
	DNSServers []string `json:"dns_servers"`
	ListenPort int      `json:"listen_port"`
	MTU        int      `json:"mtu"`
	// Protocol selects STUN discovery: "ipv4", "ipv6" or "dualstack".
	Protocol string `json:"protocol"`
}

type peerConfig struct {
	Name                string   `json:"name"`
	Description         string   `json:"description"`
	PublicKey           string   `json:"public_key"`
	PresharedKey        string   `json:"preshared_key"`
	AllowedIPs          []string `json:"allowed_ips"`
	Endpoint            string   `json:"endpoint"`
	Plugin              string   `json:"plugin"`
	Protocol            string   `json:"protocol"`
	PersistentKeepalive int      `json:"persistent_keepalive"`
}

type pluginDef struct {
	Instance string `json:"instance"`
	Type     string `json:"type"`
	Name     string `json:"name"`
	// Values are free-form like the desktop YAML config: a plugin key may
	// hold a string, a list (opendht's "endpoints"), or a number. The
	// plugins' own config helpers deal with the types.
	Config map[string]any `json:"config"`
}

type stunConfig struct {
	Addresses []string `json:"addresses"`
}

type logConfig struct {
	Level string `json:"level"`
}

// defaultStunServer matches the stunmesh-go default.
const defaultStunServer = "stun.l.google.com:19302"

func parseConfig(configJSON string) (*tunnelConfig, error) {
	cfg := tunnelConfig{Interface: ifaceConfig{MTU: 1420}, RefreshIntervalSeconds: 180}
	if err := validation.DecodeJSON([]byte(configJSON), &cfg); err != nil {
		return nil, err
	}
	if cfg.Interface.PrivateKey == "" {
		return nil, errors.New("interface.private_key is required")
	}
	if _, err := keyToHex(cfg.Interface.PrivateKey); err != nil {
		return nil, fmt.Errorf("interface.private_key: %w", err)
	}
	if len(cfg.Peers) > validation.MaxPeers || len(cfg.Plugins) > validation.MaxStores || len(cfg.Stun.Addresses) > validation.MaxServers {
		return nil, errors.New("too many peers, stores or STUN servers")
	}
	if cfg.RefreshIntervalSeconds < 1 || cfg.RefreshIntervalSeconds > 240 {
		return nil, errors.New("refresh interval must be within 1–240 seconds")
	}
	if cfg.Interface.MTU < 1280 || cfg.Interface.MTU > 1500 {
		return nil, errors.New("MTU must be within 1280–1500")
	}
	if len(cfg.Interface.Addresses) > validation.MaxRoutes || len(cfg.Interface.DNSServers) > validation.MaxServers {
		return nil, errors.New("too many interface addresses or DNS servers")
	}
	for _, addr := range cfg.Interface.Addresses {
		if _, err := validation.Prefix(addr); err != nil {
			return nil, errors.New("invalid interface address")
		}
	}
	seen := make(map[string]bool)
	stores := make(map[string]bool)
	for _, def := range cfg.Plugins {
		if def.Instance == "" || stores[def.Instance] || len(def.Instance) > 128 {
			return nil, errors.New("invalid or duplicate store instance")
		}
		stores[def.Instance] = true
		conf := pluginapi.PluginConfig{"name": def.Name}
		for k, v := range def.Config {
			if k == "name" {
				return nil, errors.New("store name must not be overridden")
			}
			conf[k] = v
		}
		if err := pluginapi.ValidateDefinition(pluginapi.PluginDefinition{Type: def.Type, Config: conf}); err != nil {
			return nil, err
		}
	}
	for i, p := range cfg.Peers {
		if p.Plugin != "" && !stores[p.Plugin] {
			return nil, errors.New("unknown peer store")
		}
		if _, err := validation.PublicKey(p.PublicKey); err != nil {
			return nil, fmt.Errorf("peer %d public_key: %w", i, err)
		}
		if seen[p.PublicKey] {
			return nil, errors.New("duplicate peer public key")
		}
		seen[p.PublicKey] = true
		if p.PresharedKey != "" {
			if _, err := keyToHex(p.PresharedKey); err != nil {
				return nil, fmt.Errorf("peer %d preshared_key: %w", i, err)
			}
		}
	}
	if cfg.Interface.Protocol != "" {
		switch cfg.Interface.Protocol {
		case "ipv4", "ipv6", "dualstack":
		default:
			return nil, errors.New("invalid interface protocol")
		}
	}
	for i, p := range cfg.Peers {
		if p.Protocol != "" {
			switch p.Protocol {
			case "ipv4", "ipv6", "prefer_ipv4", "prefer_ipv6":
			default:
				return nil, fmt.Errorf("invalid protocol for peer %d", i)
			}
		}
	}
	if cfg.Interface.Protocol == "" {
		cfg.Interface.Protocol = "ipv4"
	}
	if len(cfg.Stun.Addresses) == 0 {
		cfg.Stun.Addresses = []string{defaultStunServer}
	}
	for _, server := range cfg.Stun.Addresses {
		if err := validation.Server(server); err != nil {
			return nil, err
		}
	}
	if _, err := buildUAPI(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// keyToBytes decodes a base64 WG key into its 32-byte form.
func keyToBytes(b64 string) ([32]byte, error) {
	return validation.Key(b64)
}

// keyToHex converts a base64 WG key to the hex form UAPI wants.
func keyToHex(b64 string) (string, error) {
	raw, err := validation.Key(b64)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}
