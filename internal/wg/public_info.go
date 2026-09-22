package wg

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type Runner func(context.Context, string, ...string) ([]byte, error)

// Public-only wg subcommands keep private keys and PSKs out of this daemon.
// wgctrl.Device/show-dump would materialize both even if we ignored the fields.
func publicInfo(ctx context.Context, name string, run Runner) (*DeviceInfo, error) {
	if name == "" || len(name) > 15 || strings.ContainsAny(name, "\x00\r\n/ \t") || strings.HasPrefix(name, "-") {
		return nil, errors.New("invalid WireGuard interface name")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	query := func(field string) (string, error) {
		b, err := run(ctx, "wg", "show", name, field)
		if err != nil {
			return "", elevationHint(err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	pub, err := query("public-key")
	if err != nil {
		return nil, err
	}
	key, err := decodeKey(pub)
	if err != nil {
		return nil, errors.New("invalid WG public key response")
	}
	portText, err := query("listen-port")
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("WG interface needs a valid listen port")
	}
	markText, err := query("fwmark")
	if err != nil {
		return nil, err
	}
	mark, err := parseFwmark(markText)
	if err != nil {
		return nil, err
	}
	peersText, err := query("peers")
	if err != nil {
		return nil, err
	}
	peers := strings.Fields(peersText)
	if len(peers) > 32 {
		return nil, errors.New("too many WireGuard peers")
	}
	info := &DeviceInfo{Name: name, PublicKey: key, ListenPort: port, FirewallMark: mark}
	for _, text := range peers {
		key, err := decodeKey(text)
		if err != nil {
			return nil, errors.New("invalid WG peer key response")
		}
		info.PeerKeys = append(info.PeerKeys, key)
	}
	return info, nil
}

type boundedOutput struct{ bytes.Buffer }

func (b *boundedOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 16*1024 {
		return 0, errors.New("WG response too large")
	}
	return b.Buffer.Write(p)
}

func defaultRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var out boundedOutput
	cmd.Stdout = &out
	// stderr is deliberately not included in diagnostics: the tool may echo
	// sensitive input on failures. The exit error contains no profile values.
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func decodeKey(text string) (Key, error) {
	var k Key
	b, err := base64.StdEncoding.Strict().DecodeString(text)
	if err != nil || len(b) != 32 {
		return k, errors.New("invalid WG key encoding")
	}
	copy(k[:], b)
	return k, nil
}

func parseFwmark(s string) (int, error) {
	if s == "off" {
		return 0, nil
	}
	if !strings.HasPrefix(s, "0x") {
		return 0, errors.New("invalid WG firewall mark")
	}
	v, err := strconv.ParseUint(s[2:], 16, 32)
	if err != nil {
		return 0, errors.New("invalid WG firewall mark")
	}
	return int(v), nil
}
