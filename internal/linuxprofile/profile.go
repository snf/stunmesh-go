// Package linuxprofile is the deliberately separate Linux enrollment boundary.
// WireGuard alone authenticates peers. This package validates local policy and
// renders native configuration; it implements no remote authentication.
package linuxprofile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/tjjh89017/stunmesh-go/internal/provision"
	"github.com/tjjh89017/stunmesh-go/internal/validation"
	"go.yaml.in/yaml/v3"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const Schema = "stunmesh-linux-v1"
const MaxBytes = 16384
const Interface = "wg0"
const ListenPort = 51832
const ProxyPort = 51834

var label = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
var hostname = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}(\.[a-z][a-z0-9-]{0,31})*$`)

type Profile struct {
	Schema          string            `json:"schema"`
	Name            string            `json:"name"`
	PrivateKey      string            `json:"private_key"`
	PresharedKey    string            `json:"preshared_key"`
	ServerPublicKey string            `json:"server_public_key"`
	Address         string            `json:"address"`
	AllowedIPs      []string          `json:"allowed_ips"`
	Endpoint        string            `json:"endpoint"`
	STUN            []string          `json:"stun_servers"`
	OpenDHT         []string          `json:"opendht"`
	Hostnames       map[string]string `json:"hostnames"`
	LANHostnames    map[string]string `json:"lan_hostnames"`
}

func (Profile) String() string     { return "LinuxProfile{redacted}" }
func (p Profile) GoString() string { return p.String() }

func Read(r io.Reader) (Profile, error) {
	b, err := io.ReadAll(io.LimitReader(r, MaxBytes+1))
	if err != nil || len(b) > MaxBytes {
		return Profile{}, errors.New("profile input exceeds bounds")
	}
	return Decode(b)
}

func Decode(b []byte) (Profile, error) {
	var p Profile
	if len(b) > MaxBytes {
		return p, errors.New("profile input exceeds bounds")
	}
	if err := validation.DecodeJSON(b, &p); err != nil {
		return Profile{}, err
	}
	// encoding/json otherwise accepts differently cased struct field names.
	var fields map[string]json.RawMessage
	if json.Unmarshal(b, &fields) != nil {
		return Profile{}, errors.New("invalid profile")
	}
	for k := range fields {
		if k != strings.ToLower(k) {
			return Profile{}, errors.New("profile fields must be lowercase")
		}
	}
	if err := p.Validate(); err != nil {
		return Profile{}, err
	}
	return p, nil
}

func (p Profile) Validate() error {
	if p.Schema != Schema || !label.MatchString(p.Name) {
		return errors.New("invalid Linux schema/name")
	}
	k, err := validation.Key(p.PrivateKey)
	if err != nil || k == [32]byte{} || k[0]&7 != 0 || k[31]&128 != 0 || k[31]&64 == 0 {
		return errors.New("invalid WireGuard private key")
	}
	if k, err := validation.Key(p.PresharedKey); err != nil || k == [32]byte{} {
		return errors.New("invalid preshared key")
	}
	if p.Address != "10.77.0.253/32" {
		return errors.New("this client reserves address 10.77.0.253/32")
	}
	// Reuse the audited enrollment validation for routes, endpoints and discovery.
	q := provision.Proposal{Schema: provision.Schema, ID: "00000000-0000-4000-8000-000000000001", Name: p.Name,
		Address: p.Address, ServerPublicKey: p.ServerPublicKey, AllowedIPs: p.AllowedIPs,
		Endpoint: p.Endpoint, Protocol: "ipv4", STUN: p.STUN, OpenDHT: p.OpenDHT, PresharedKey: p.PresharedKey}
	if err := q.Validate(); err != nil {
		return err
	}
	ep, err := validation.Endpoint(p.Endpoint)
	if err != nil || !ep.Addr().Is4() {
		return errors.New("numeric IPv4 bootstrap required")
	}
	allowed := map[string]bool{}
	for _, s := range p.AllowedIPs {
		switch s {
		case "10.77.0.1/32", "10.77.0.21/32", "10.77.0.23/32", "10.77.1.0/24":
		default:
			return errors.New("unapproved service route")
		}
		if allowed[s] {
			return errors.New("duplicate route")
		}
		allowed[s] = true
	}
	if !allowed["10.77.0.1/32"] {
		return errors.New("NAS service route required")
	}
	if len(p.Hostnames) == 0 || len(p.Hostnames) > 16 || len(p.LANHostnames) > 16 {
		return errors.New("hostname count outside bounds")
	}
	for name, s := range p.Hostnames {
		if !validName(name) || strings.HasSuffix(name, "-lan") {
			return errors.New("invalid VPN hostname")
		}
		ip, err := netip.ParseAddr(s)
		if err != nil || !allowed[ip.String()+"/32"] {
			return errors.New("hostname requires an exact service route")
		}
		if _, exists := p.LANHostnames[name]; exists {
			return errors.New("hostname collision")
		}
	}
	lan := netip.MustParsePrefix("192.168.0.0/24")
	for name, s := range p.LANHostnames {
		ip, err := netip.ParseAddr(s)
		if !validName(name) || !strings.HasSuffix(name, "-lan") || err != nil || !lan.Contains(ip) || s == "192.168.0.0" || s == "192.168.0.255" {
			return errors.New("invalid LAN recovery alias")
		}
	}
	if p.PublicKey() == p.ServerPublicKey {
		return errors.New("client and server identities must differ")
	}
	return nil
}

func validName(s string) bool {
	return len(s) <= 128 && hostname.MatchString(s) && s != "localhost" && !strings.HasSuffix(s, ".localhost")
}

func (p Profile) PublicKey() string {
	k, _ := wgtypes.ParseKey(p.PrivateKey)
	return k.PublicKey().String()
}

// Public deliberately excludes both secrets, even on a validation failure.
func (p Profile) Public() map[string]any {
	return map[string]any{"schema": p.Schema, "name": p.Name, "public_key": p.PublicKey(), "server_public_key": p.ServerPublicKey, "address": p.Address, "allowed_ips": p.AllowedIPs, "endpoint": p.Endpoint, "hostnames": p.Hostnames, "lan_hostnames": p.LANHostnames, "listen_port": ListenPort, "proxy_port": ProxyPort}
}

func (p Profile) WireGuard() []byte {
	return []byte(fmt.Sprintf("[Interface]\nPrivateKey = %s\nListenPort = %d\n\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s\nEndpoint = %s\nPersistentKeepalive = 25\n", p.PrivateKey, ListenPort, p.ServerPublicKey, p.PresharedKey, strings.Join(p.AllowedIPs, ", "), p.Endpoint))
}

func (p Profile) Discovery() ([]byte, error) {
	return yaml.Marshal(map[string]any{
		"refresh_interval": "180s", "interfaces": map[string]any{Interface: map[string]any{"protocol": "ipv4", "proxy": map[string]int{"listen": ProxyPort}, "peers": map[string]any{"nas": map[string]string{"public_key": p.ServerPublicKey, "plugin": "dht", "protocol": "ipv4"}}}},
		"plugins": map[string]any{"dht": map[string]any{"type": "builtin", "name": "opendht", "endpoints": p.OpenDHT, "timeout": "10s"}},
		"stun":    map[string]any{"addresses": p.STUN}, "log": map[string]string{"level": "info", "format": "json"},
	})
}

// Issue accepts a secret-free template and generates keys using the official wg
// command. Output is confidential; callers must capture it in an exclusive 0600
// file. This function is used only by the one-shot provision tool.
func Issue(raw []byte, wg string) ([]byte, error) {
	var fields map[string]json.RawMessage
	if len(raw) > MaxBytes || validation.DecodeJSON(raw, &fields) != nil {
		return nil, errors.New("invalid Linux issuance template")
	}
	for key := range fields {
		if key != strings.ToLower(key) || key == "private_key" || key == "preshared_key" {
			return nil, errors.New("issuance accepts no secret fields")
		}
	}
	for field, cmd := range map[string]string{"private_key": "genkey", "preshared_key": "genpsk"} {
		b, err := exec.Command(wg, cmd).Output()
		if err != nil {
			return nil, errors.New("official wg key generation failed")
		}
		fields[field], _ = json.Marshal(strings.TrimSpace(string(b)))
	}
	b, _ := json.Marshal(fields)
	p, err := Decode(b)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(p, "", "  ")
}

func Load(path string) (Profile, error) {
	f, err := os.Open(path)
	if err != nil {
		return Profile{}, errors.New("cannot open Linux profile")
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		return Profile{}, errors.New("profile must be a private regular file")
	}
	return Read(f)
}

// WriteNew never follows an existing file or leaves a partial valid-looking one.
func WriteNew(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("output must be a new private file")
	}
	_, err = io.Copy(f, bytes.NewReader(b))
	err = errors.Join(err, f.Sync(), f.Close())
	if err != nil {
		_ = os.Remove(path)
		return errors.New("cannot write complete output")
	}
	return nil
}
