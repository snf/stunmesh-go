// Package validation contains the small shared input boundary. Errors name
// fields/categories, never echo untrusted configuration or key material.
package validation

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

const (
	MaxConfigBytes = 256 * 1024
	MaxPeers       = 32
	MaxStores      = 8
	MaxRoutes      = 64
	MaxServers     = 8
)

func Key(text string) ([32]byte, error) {
	var key [32]byte
	if len(text) != 44 {
		return key, errors.New("key must be canonical base64 for 32 bytes")
	}
	b, err := base64.StdEncoding.Strict().DecodeString(text)
	if err != nil || len(b) != len(key) || base64.StdEncoding.EncodeToString(b) != text {
		return key, errors.New("invalid key encoding")
	}
	copy(key[:], b)
	return key, nil
}

// PublicKey rejects low-order X25519 points using the standard library. This
// is input validation only; WireGuard alone authenticates the remote peer.
func PublicKey(text string) ([32]byte, error) {
	k, err := Key(text)
	if err != nil {
		return k, err
	}
	pub, err := ecdh.X25519().NewPublicKey(k[:])
	if err != nil {
		return k, errors.New("invalid public key")
	}
	scalar := [32]byte{42}
	probe, _ := ecdh.X25519().NewPrivateKey(scalar[:])
	if _, err := probe.ECDH(pub); err != nil {
		return k, errors.New("low-order public key")
	}
	return k, nil
}

// Endpoint parses numeric addresses only, so rendering cannot interpret UAPI
// lines or cause an implicit hostname lookup. Discovery applies extra policy.
func Endpoint(text string) (netip.AddrPort, error) {
	if len(text) > 256 {
		return netip.AddrPort{}, errors.New("endpoint too long")
	}
	ep, err := netip.ParseAddrPort(text)
	if err != nil || ep.Port() == 0 || ep.Addr().Zone() != "" || ep.Addr().IsUnspecified() || ep.Addr().IsMulticast() || ep.Addr().IsLinkLocalUnicast() {
		return netip.AddrPort{}, errors.New("invalid numeric endpoint")
	}
	return netip.AddrPortFrom(ep.Addr().Unmap(), ep.Port()), nil
}

func HostPort(host string, port int) (netip.AddrPort, error) {
	if port < 1 || port > 65535 {
		return netip.AddrPort{}, errors.New("endpoint port outside 1–65535")
	}
	return Endpoint(net.JoinHostPort(host, strconv.Itoa(port)))
}

func Prefix(text string) (netip.Prefix, error) {
	if len(text) > 64 {
		return netip.Prefix{}, errors.New("prefix too long")
	}
	p, err := netip.ParsePrefix(text)
	if err != nil || p.Addr().Is4In6() || p.Addr().IsMulticast() || p.Addr().IsUnspecified() || p.Addr().IsLoopback() || p.Addr().IsLinkLocalUnicast() {
		return netip.Prefix{}, errors.New("invalid prefix")
	}
	return p, nil
}

// ServiceRoute deliberately limits this home fork to small service ranges.
// With at most 64 routes/peer and 32 peers, these bounds also prohibit a
// catch-all assembled from individually non-default routes.
func ServiceRoute(text string) (netip.Prefix, error) {
	p, err := Prefix(text)
	if err != nil {
		return p, err
	}
	minBits := 64
	if p.Addr().Is4() {
		minBits = 24
	}
	if p.Bits() < minBits {
		return netip.Prefix{}, errors.New("service route must be /24 or narrower for IPv4, /64 for IPv6")
	}
	return p.Masked(), nil
}

func Server(text string) error {
	if len(text) > 256 || strings.ContainsAny(text, "\r\n\t /?#@") {
		return errors.New("invalid STUN server")
	}
	host, port, err := net.SplitHostPort(text)
	p, portErr := strconv.Atoi(port)
	if err != nil || host == "" || portErr != nil || p < 1 || p > 65535 {
		return errors.New("invalid STUN server address/port")
	}
	return nil
}

// DecodeJSON rejects duplicates (including case variants), nulls, excessive
// nesting, unknown struct fields and trailing documents before decoding.
func DecodeJSON(raw []byte, out any) error {
	if len(raw) == 0 || len(raw) > MaxConfigBytes {
		return errors.New("configuration size outside bounds")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	var check func(int) error
	check = func(depth int) error {
		if depth > 16 {
			return errors.New("configuration nesting too deep")
		}
		t, err := d.Token()
		if err != nil || t == nil {
			return errors.New("invalid JSON value")
		}
		switch t {
		case json.Delim('{'):
			seen := map[string]bool{}
			for d.More() {
				k, err := d.Token()
				name, ok := k.(string)
				name = strings.ToLower(name)
				if err != nil || !ok || seen[name] {
					return errors.New("duplicate or invalid JSON field")
				}
				seen[name] = true
				if err := check(depth + 1); err != nil {
					return err
				}
			}
			if end, err := d.Token(); err != nil || end != json.Delim('}') {
				return errors.New("invalid JSON object")
			}
		case json.Delim('['):
			for d.More() {
				if err := check(depth + 1); err != nil {
					return err
				}
			}
			if end, err := d.Token(); err != nil || end != json.Delim(']') {
				return errors.New("invalid JSON array")
			}
		}
		return nil
	}
	if err := check(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing JSON data")
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return errors.New("configuration schema mismatch")
	}
	return nil
}
