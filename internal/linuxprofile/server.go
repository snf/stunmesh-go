package linuxprofile

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/tjjh89017/stunmesh-go/internal/config"
	"github.com/tjjh89017/stunmesh-go/internal/validation"
	"go.yaml.in/yaml/v3"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var privateLine = regexp.MustCompile(`(?m)^PrivateKey\s*=\s*(\S+)\s*$`)
var routeLine = regexp.MustCompile(`(?m)^AllowedIPs\s*=\s*(.+)$`)

type Server struct {
	WG        string
	YAML      map[string]any
	Peers     map[string]any
	PublicKey string
	STUN      []string
	DHT       []string
}

func boundedFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("cannot read server configuration")
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, validation.MaxConfigBytes+1))
	if err != nil || len(b) > validation.MaxConfigBytes {
		return nil, errors.New("server configuration exceeds bounds")
	}
	return b, nil
}
func LoadServer(dir string) (Server, error) {
	var s Server
	wg, err := boundedFile(filepath.Join(dir, "wg0.conf"))
	if err != nil {
		return s, err
	}
	s.WG = string(wg)
	key := privateLine.FindAllStringSubmatch(s.WG, -1)
	if len(key) != 1 {
		return s, errors.New("expected one server interface identity")
	}
	k, err := wgtypes.ParseKey(key[0][1])
	if err != nil {
		return s, errors.New("invalid server private key")
	}
	s.PublicKey = k.PublicKey().String()
	ymlPath := filepath.Join(dir, "stunmesh.yml")
	cfg, err := config.Load(ymlPath, "")
	if err != nil {
		return s, errors.New("invalid server discovery config")
	}
	s.STUN = cfg.Stun.GetServers()
	b, err := boundedFile(ymlPath)
	if err != nil {
		return s, err
	}
	if yaml.Unmarshal(b, &s.YAML) != nil {
		return s, errors.New("invalid server YAML")
	}
	lookup := func(m map[string]any, key string) (map[string]any, error) {
		v, ok := m[key].(map[string]any)
		if !ok {
			return nil, errors.New("unsupported server YAML layout")
		}
		return v, nil
	}
	ifs, err := lookup(s.YAML, "interfaces")
	if err != nil {
		return s, err
	}
	iface, err := lookup(ifs, "wg0")
	if err != nil {
		return s, err
	}
	s.Peers, err = lookup(iface, "peers")
	if err != nil {
		return s, err
	}
	pl, err := lookup(s.YAML, "plugins")
	if err != nil {
		return s, err
	}
	dht, err := lookup(pl, "dht")
	if err != nil {
		return s, err
	}
	if dht["name"] != "opendht" || dht["type"] != "builtin" {
		return s, errors.New("expected built-in OpenDHT plugin")
	}
	endpoints, ok := dht["endpoints"].([]any)
	if !ok {
		return s, errors.New("expected OpenDHT endpoint list")
	}
	for _, v := range endpoints {
		text, ok := v.(string)
		if !ok {
			return s, errors.New("invalid OpenDHT endpoint")
		}
		s.DHT = append(s.DHT, text)
	}
	return s, nil
}
func (s Server) Public() map[string]any {
	routes := []string{}
	for _, line := range routeLine.FindAllStringSubmatch(s.WG, -1) {
		for _, r := range strings.Split(line[1], ",") {
			routes = append(routes, strings.TrimSpace(r))
		}
	}
	return map[string]any{"server_public_key": s.PublicKey, "stun_servers": s.STUN, "opendht": s.DHT, "peer_addresses": routes}
}

// Edited returns confidential candidate files. It never changes the server or
// authorizes a live peer. The caller validates them using wg in an isolated
// namespace, then performs an explicit, locked file transaction and restart.
func (s Server) Edited(p Profile, revoke bool) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if p.ServerPublicKey != s.PublicKey {
		return nil, errors.New("profile belongs to another server")
	}
	begin := "# BEGIN LINUX " + p.Name + "\n"
	end := "# END LINUX " + p.Name + "\n"
	name := "linux-" + p.Name
	start := strings.Index(s.WG, begin)
	finish := strings.Index(s.WG, end)
	_, discoveryExists := s.Peers[name]
	if start >= 0 || finish >= 0 || discoveryExists {
		if start < 0 || finish < start || !discoveryExists || strings.Count(s.WG, begin) != 1 || strings.Count(s.WG, end) != 1 {
			return nil, errors.New("inconsistent managed peer; review private files")
		}
		block := s.WG[start:finish]
		peer, ok := s.Peers[name].(map[string]any)
		if !ok || peer["public_key"] != p.PublicKey() || !strings.Contains(block, "PublicKey = "+p.PublicKey()+"\n") {
			return nil, errors.New("refusing to replace a different managed identity")
		}
		s.WG = s.WG[:start] + s.WG[finish+len(end):]
		delete(s.Peers, name)
	}
	if !revoke {
		ip := netip.MustParsePrefix(p.Address).Addr()
		for _, line := range routeLine.FindAllStringSubmatch(s.WG, -1) {
			for _, r := range strings.Split(line[1], ",") {
				prefix, err := netip.ParsePrefix(strings.TrimSpace(r))
				if err != nil || prefix.Contains(ip) {
					return nil, errors.New("existing server peer address collision")
				}
			}
		}
		if strings.Contains(s.WG, p.PublicKey()) {
			return nil, errors.New("identity already belongs to another peer")
		}
		s.WG = strings.TrimRight(s.WG, "\n") + "\n\n" + begin + fmt.Sprintf("[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s\nPersistentKeepalive = 25\n", p.PublicKey(), p.PresharedKey, p.Address) + end
		s.Peers[name] = map[string]any{"public_key": p.PublicKey(), "plugin": "dht", "protocol": "ipv4"}
	}
	yml, err := yaml.Marshal(s.YAML)
	if err != nil {
		return nil, errors.New("cannot render discovery config")
	}
	return json.Marshal(map[string]string{"wg0.conf": s.WG, "stunmesh.yml": string(yml)})
}
