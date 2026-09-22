// Package discovery defines unauthenticated, non-authorizing endpoint hints.
// Only trusted local configuration can choose a WireGuard peer or its routes.
package discovery

import (
	"encoding/json"
	"errors"
	"net/netip"

	"github.com/tjjh89017/stunmesh-go/internal/validation"
)

const Namespace = "stunmesh-hints-v2"
const MaxRecordBytes = 1024

type Record struct {
	Version int    `json:"version"`
	IPv4    string `json:"ipv4,omitempty"`
	IPv6    string `json:"ipv6,omitempty"`
}

func Encode(r Record) (string, error) {
	r.Version = 2
	if err := r.validate(); err != nil {
		return "", err
	}
	b, err := json.Marshal(r)
	return string(b), err
}

func Decode(raw string) (Record, error) {
	var r Record
	if len(raw) > MaxRecordBytes {
		return r, errors.New("discovery record too large")
	}
	if err := validation.DecodeJSON([]byte(raw), &r); err != nil {
		return r, errors.New("invalid discovery schema")
	}
	return r, r.validate()
}

func (r Record) validate() error {
	if r.Version != 2 || r.IPv4 == "" && r.IPv6 == "" {
		return errors.New("unsupported or empty discovery record")
	}
	for family, raw := range map[int]string{4: r.IPv4, 6: r.IPv6} {
		if raw == "" {
			continue
		}
		ep, err := validation.Endpoint(raw)
		if err != nil || ep.Addr().IsLoopback() || !ep.Addr().IsGlobalUnicast() || ep.Addr().Is4() != (family == 4) {
			return errors.New("invalid discovery endpoint")
		}
	}
	return nil
}

// Allowed restricts unsolicited hints. Private/CGNAT endpoints need an explicit
// locally configured private subnet; a store cannot supply that permission.
func Allowed(endpoint string, localLAN []netip.Prefix) bool {
	ep, err := validation.Endpoint(endpoint)
	if err != nil || ep.Addr().IsLoopback() || !ep.Addr().IsGlobalUnicast() {
		return false
	}
	if !ep.Addr().IsPrivate() && !netip.MustParsePrefix("100.64.0.0/10").Contains(ep.Addr()) {
		return true
	}
	for _, p := range localLAN {
		if p.Contains(ep.Addr()) {
			return true
		}
	}
	return false
}
