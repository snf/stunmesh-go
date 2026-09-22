//go:build mobile

package mobile

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/tjjh89017/stunmesh-go/internal/validation"
)

// buildUAPI renders the config as a wireguard-go IpcSet string. Peer
// endpoints set here are only the optional static initial endpoints; the
// STUNMESH controllers overwrite them at run time with discovered ones.
func buildUAPI(cfg *tunnelConfig) (string, error) {
	var b strings.Builder
	if cfg == nil || cfg.Interface.ListenPort < 0 || cfg.Interface.ListenPort > 65535 || len(cfg.Peers) > validation.MaxPeers {
		return "", errors.New("invalid interface port or peer count")
	}

	privHex, err := keyToHex(cfg.Interface.PrivateKey)
	if err != nil {
		return "", err
	}
	fmt.Fprintf(&b, "private_key=%s\n", privHex)
	if cfg.Interface.ListenPort > 0 {
		fmt.Fprintf(&b, "listen_port=%d\n", cfg.Interface.ListenPort)
	}
	b.WriteString("replace_peers=true\n")

	seen := make(map[[32]byte]bool)
	for _, p := range cfg.Peers {
		pub, err := validation.PublicKey(p.PublicKey)
		if err != nil {
			return "", err
		}
		if seen[pub] {
			return "", errors.New("duplicate peer public key")
		}
		seen[pub] = true
		if p.PersistentKeepalive < 0 || p.PersistentKeepalive > 65535 || len(p.AllowedIPs) > validation.MaxRoutes {
			return "", errors.New("invalid keepalive or route count")
		}
		fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(pub[:]))
		if p.PresharedKey != "" {
			pskHex, err := keyToHex(p.PresharedKey)
			if err != nil {
				return "", err
			}
			fmt.Fprintf(&b, "preshared_key=%s\n", pskHex)
		}
		if p.Endpoint != "" {
			ep, err := validation.Endpoint(p.Endpoint)
			if err != nil {
				return "", err
			}
			fmt.Fprintf(&b, "endpoint=%s\n", ep.String())
		}
		if p.PersistentKeepalive > 0 {
			fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", p.PersistentKeepalive)
		}
		b.WriteString("replace_allowed_ips=true\n")
		for _, cidr := range p.AllowedIPs {
			route, err := validation.ServiceRoute(cidr)
			if err != nil {
				return "", err
			}
			fmt.Fprintf(&b, "allowed_ip=%s\n", route.String())
		}
	}

	return b.String(), nil
}

// buildPeerEndpointUAPI renders the run-time endpoint update for one peer.
// This is the only UAPI write the STUNMESH logic performs after start; the
// device applies it without a restart.
func buildPeerEndpointUAPI(publicKeyB64, endpoint string) (string, error) {
	pub, err := validation.PublicKey(publicKeyB64)
	if err != nil {
		return "", err
	}
	ep, err := validation.Endpoint(endpoint)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("public_key=%s\nupdate_only=true\nendpoint=%s\n", hex.EncodeToString(pub[:]), ep.String()), nil
}
