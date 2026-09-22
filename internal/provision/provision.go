// Package provision validates public enrollment paperwork. It never generates,
// receives or exports a phone private key or PSK, and never authorizes a peer.
package provision

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/tjjh89017/stunmesh-go/internal/plugin/builtin/opendht"
	"github.com/tjjh89017/stunmesh-go/internal/validation"
	"github.com/tjjh89017/stunmesh-go/pluginapi"
)

const Schema = "stunmesh-enroll-v1"
const MaxBytes = 2048 // Fits a practical single QR; ordinary profile import is larger.
var uuid = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

type Proposal struct {
	Schema          string   `json:"schema"`
	ID              string   `json:"proposal_id"`
	Name            string   `json:"name"`
	Address         string   `json:"address"`
	ServerPublicKey string   `json:"server_public_key"`
	AllowedIPs      []string `json:"allowed_ips"`
	STUN            []string `json:"stun_servers"`
	OpenDHT         []string `json:"opendht"`
	Endpoint        string   `json:"endpoint,omitempty"`
	Protocol        string   `json:"protocol"`
	PSKRequired     bool     `json:"psk_required"`
}
type Reply struct {
	Schema    string   `json:"schema"`
	ID        string   `json:"proposal_id"`
	PublicKey string   `json:"public_key"`
	Addresses []string `json:"addresses"`
}

func NewID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("system randomness unavailable")
	}
	b[6] = b[6]&15 | 64
	b[8] = b[8]&63 | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}
func (p Proposal) Validate() error {
	bad := errors.New("invalid public enrollment; check schema, keys, address, narrow routes and origins")
	if p.Schema != Schema || !uuid.MatchString(p.ID) || len(p.Name) < 1 || len(p.Name) > 128 || strings.ContainsAny(p.Name, "\r\n\t") {
		return bad
	}
	if _, err := validation.PublicKey(p.ServerPublicKey); err != nil {
		return bad
	}
	a, err := validation.Prefix(p.Address)
	if err != nil || a.Bits() != a.Addr().BitLen() {
		return bad
	}
	if len(p.AllowedIPs) < 1 || len(p.AllowedIPs) > validation.MaxRoutes || len(p.STUN) < 1 || len(p.STUN) > validation.MaxServers {
		return bad
	}
	seen := map[string]bool{}
	for _, s := range p.AllowedIPs {
		r, e := validation.ServiceRoute(s)
		if e != nil || seen[r.String()] {
			return bad
		}
		seen[r.String()] = true
	}
	for _, s := range p.STUN {
		if validation.Server(s) != nil {
			return bad
		}
	}
	if p.Endpoint != "" {
		e, err := validation.Endpoint(p.Endpoint)
		if err != nil || e.Addr().IsLoopback() {
			return bad
		}
	}
	switch p.Protocol {
	case "ipv4", "ipv6", "prefer_ipv4", "prefer_ipv6":
	default:
		return bad
	}
	store, err := opendht.NewOpenDHTPlugin(pluginapi.PluginConfig{"name": "opendht", "endpoints": p.OpenDHT})
	if err != nil {
		return bad
	}
	_ = store.(*opendht.OpenDHTPlugin).Close()
	return nil
}
func (p Proposal) Encode() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(p)
	if len(b) > MaxBytes {
		return nil, errors.New("public proposal exceeds QR limit")
	}
	return b, err
}
func Decode(b []byte) (Proposal, error) {
	var p Proposal
	if len(b) > MaxBytes {
		return p, errors.New("public proposal too large")
	}
	if err := validation.DecodeJSON(b, &p); err != nil {
		return p, err
	}
	return p, p.Validate()
}
func CheckReply(p Proposal, b []byte) (Reply, error) {
	var r Reply
	if err := p.Validate(); err != nil {
		return r, err
	}
	if len(b) > MaxBytes {
		return r, errors.New("public reply too large")
	}
	if err := validation.DecodeJSON(b, &r); err != nil {
		return r, err
	}
	if r.Schema != "stunmesh-peer-v1" || r.ID != p.ID || len(r.Addresses) != 1 || r.Addresses[0] != p.Address || r.PublicKey == p.ServerPublicKey {
		return r, errors.New("reply does not match proposal")
	}
	if _, err := validation.PublicKey(r.PublicKey); err != nil {
		return r, err
	}
	return r, nil
}
