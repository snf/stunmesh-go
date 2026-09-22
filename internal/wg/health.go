package wg

import (
	"context"
	"encoding/base64"
	"errors"
	"github.com/tjjh89017/stunmesh-go/internal/discovery"
	"github.com/tjjh89017/stunmesh-go/internal/validation"
	"strconv"
	"strings"
	"time"
)

// PeerHealth reads only public WG fields. Failed/ambiguous reads never justify
// overwriting a potentially working endpoint.
func (c *ctrlClient) PeerHealth(ctx context.Context, name string, key Key) (discovery.Health, error) {
	var h discovery.Health
	if name == "" || len(name) > 15 || strings.ContainsAny(name, "\x00\r\n/ \t") || strings.HasPrefix(name, "-") {
		return h, errors.New("invalid WG interface")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	want := base64.StdEncoding.EncodeToString(key[:])
	for _, field := range []string{"endpoints", "latest-handshakes", "transfer"} {
		b, err := c.runner(ctx, "wg", "show", name, field)
		if err != nil {
			return h, err
		}
		if len(b) > 16384 {
			return h, errors.New("oversized WG health response")
		}
		found := false
		for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			v := strings.Fields(line)
			if len(v) == 0 || v[0] != want {
				continue
			}
			if found || len(v) < 2 {
				return h, errors.New("invalid WG health response")
			}
			found = true
			switch field {
			case "endpoints":
				if v[1] != "(none)" {
					ep, err := validation.Endpoint(v[1])
					if err != nil {
						return h, err
					}
					h.Endpoint = ep.String()
				}
			case "latest-handshakes":
				n, err := strconv.ParseInt(v[1], 10, 64)
				if err != nil || n < 0 {
					return h, errors.New("invalid handshake time")
				}
				if n > 0 {
					h.Handshake = time.Unix(n, 0)
				}
			case "transfer":
				if len(v) != 3 {
					return h, errors.New("invalid transfer count")
				}
				n, err := strconv.ParseUint(v[1], 10, 64)
				if err != nil {
					return h, errors.New("invalid receive count")
				}
				h.Received = n
			}
		}
		if !found {
			return h, errors.New("WireGuard peer no longer exists")
		}
	}
	return h, nil
}
