//go:build mobile && (linux || android)

package mobile

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"github.com/tjjh89017/stunmesh-go/internal/discovery"
	"strconv"
	"time"
)

// WireGuard's stock UAPI includes secrets. The writer never copies or logs
// those lines: only public health fields leave this data-plane adapter. Raw
// private material still exists inside wireguard-go, as documented in the threat model.
type healthWriter struct{ peers map[string]discovery.Health }

func (w *healthWriter) Write(b []byte) (int, error) {
	size := len(b)
	if size > 128*1024 {
		return 0, errors.New("oversized WireGuard status")
	}
	peer := ""
	for len(b) > 0 {
		var line []byte
		line, b, _ = bytes.Cut(b, []byte{'\n'})
		field, value, ok := bytes.Cut(line, []byte{'='})
		if !ok {
			continue
		}
		switch string(field) {
		case "public_key":
			raw, err := hex.DecodeString(string(value))
			if err != nil || len(raw) != 32 {
				return 0, errors.New("invalid public health key")
			}
			peer = base64.StdEncoding.EncodeToString(raw)
			w.peers[peer] = discovery.Health{}
		case "endpoint", "last_handshake_time_sec", "rx_bytes":
			if peer == "" {
				continue
			}
			h := w.peers[peer]
			switch string(field) {
			case "endpoint":
				h.Endpoint = string(value)
			case "last_handshake_time_sec":
				n, err := strconv.ParseInt(string(value), 10, 64)
				if err != nil {
					return 0, err
				}
				if n > 0 {
					h.Handshake = time.Unix(n, 0)
				}
			case "rx_bytes":
				n, err := strconv.ParseUint(string(value), 10, 64)
				if err != nil {
					return 0, err
				}
				h.Received = n
			}
			w.peers[peer] = h
		}
	}
	return size, nil
}
func (n *Node) peerHealth() (map[string]discovery.Health, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.running || n.dev == nil {
		return nil, errors.New("device unavailable")
	}
	w := &healthWriter{peers: map[string]discovery.Health{}}
	if err := n.dev.IpcGetOperation(w); err != nil {
		return nil, errors.New("WireGuard health unavailable")
	}
	return w.peers, nil
}
